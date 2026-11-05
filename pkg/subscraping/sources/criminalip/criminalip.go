// Package criminalip logic
package criminalip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// maxPolls bounds how many times the scan status is checked.
	maxPolls = 10
	// pollInterval is the delay between status checks.
	pollInterval = 3 * time.Second
)

// reportsListResponse represents existing reports for a domain.
type reportsListResponse struct {
	Data struct {
		Reports []struct {
			ScanID json.RawMessage `json:"scan_id"`
		} `json:"reports"`
	} `json:"data"`
}

// scanResponse is the JSON payload returned when a scan is submitted.
type scanResponse struct {
	Data struct {
		ScanID json.RawMessage `json:"scan_id"`
	} `json:"data"`
}

// statusResponse is the JSON payload returned by the scan status endpoint.
type statusResponse struct {
	Data struct {
		ScanPercentage int `json:"scan_percentage"`
	} `json:"data"`
}

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		// Pick an API key
		apiKey := subscraping.PickRandom(apiKeys, s.Name())
		if apiKey == "" {
			stats.Skipped = true
			return
		}

		fail := func(err error) {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
		}

		// emit forwards every in-scope subdomain found in text. It returns false
		// once the context is cancelled.
		emit := func(text string) bool {
			for _, subdomain := range session.Extractor.Extract(text) {
				select {
				case <-ctx.Done():
					return false
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
			}
			return true
		}

		headers := map[string]string{"x-api-key": apiKey}

		var scanID string

		// First check if an existing report is already available.
		reportsURL := "https://api.criminalip.io/v1/domain/reports?query=" + url.QueryEscape(domain)
		stats.Requests++
		if body, err := request(ctx, session, http.MethodGet, reportsURL, headers, nil, apiKey); err == nil {
			var list reportsListResponse
			if json.Unmarshal(body, &list) == nil && len(list.Data.Reports) > 0 {
				scanID = strings.Trim(string(list.Data.Reports[0].ScanID), "\" \t\r\n")
			}
		}

		// If no existing report, submit a domain scan.
		if scanID == "" {
			formHeaders := map[string]string{
				"x-api-key":    apiKey,
				"Content-Type": "application/x-www-form-urlencoded",
			}
			form := url.Values{"query": {domain}}
			stats.Requests++
			body, err := request(ctx, session, http.MethodPost, "https://api.criminalip.io/v1/domain/scan", formHeaders, strings.NewReader(form.Encode()), apiKey)
			if err != nil {
				fail(err)
				return
			}

			var scan scanResponse
			if err := json.Unmarshal(body, &scan); err != nil {
				fail(err)
				return
			}
			scanID = strings.Trim(string(scan.Data.ScanID), "\" \t\r\n")
			if scanID == "" {
				fail(fmt.Errorf("criminalip: scan submission returned no scan_id"))
				return
			}

			// Poll until the scan completes or the poll budget is exhausted.
			statusURL := "https://api.criminalip.io/v1/domain/status/" + url.PathEscape(scanID)
			for attempt := 1; attempt <= maxPolls; attempt++ {
				if attempt > 1 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(pollInterval):
					}
				}

				stats.Requests++
				body, err = request(ctx, session, http.MethodGet, statusURL, headers, nil, apiKey)
				if err != nil {
					fail(err)
					return
				}

				var status statusResponse
				if err := json.Unmarshal(body, &status); err != nil {
					fail(err)
					return
				}
				if status.Data.ScanPercentage >= 100 {
					break
				}
			}
		}

		// Fetch the report.
		reportURL := "https://api.criminalip.io/v2/domain/report/" + url.PathEscape(scanID)
		stats.Requests++
		body, err := request(ctx, session, http.MethodGet, reportURL, headers, nil, apiKey)
		if err != nil {
			fail(err)
			return
		}

		for _, subdomain := range session.Extractor.Extract(string(body)) {
			if !emit(subdomain) {
				return
			}
		}
	}()

	return results
}

// request performs an HTTP request and returns the full response body. Secrets
// are scrubbed from returned errors, since transport errors echo the request URL.
func request(ctx context.Context, session *subscraping.Session, method, apiURL string, headers map[string]string, body io.Reader, secrets ...string) ([]byte, error) {
	resp, err := session.HTTPRequest(ctx, method, apiURL, "", headers, body)
	if err != nil {
		return nil, redact(err, secrets...)
	}
	defer session.DiscardHTTPResponse(resp)

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, redact(err, secrets...)
	}
	return data, nil
}

// redact returns err with every non-empty secret replaced by a placeholder.
func redact(err error, secrets ...string) error {
	msg := err.Error()
	for _, secret := range secrets {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[REDACTED]")
		}
	}
	return errors.New(msg)
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "criminalip"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
