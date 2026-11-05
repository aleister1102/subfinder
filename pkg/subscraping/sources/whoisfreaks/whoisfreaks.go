// Package whoisfreaks logic
package whoisfreaks

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

// subdomainsResponse is the JSON payload returned by the subdomains endpoint.
type subdomainsResponse struct {
	Status      bool   `json:"status"`
	Message     string `json:"message"`
	CurrentPage int    `json:"current_page"`
	TotalPages  int    `json:"total_pages"`
	Subdomains  []struct {
		Subdomain string `json:"subdomain"`
	} `json:"subdomains"`
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

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		fail := func(err error) {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
		}

		// emit forwards every in-scope subdomain found in text. It returns false
		// once the context is cancelled or the result limit has been reached.
		emit := func(text string) bool {
			for _, subdomain := range session.Extractor.Extract(text) {
				select {
				case <-ctx.Done():
					return false
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
				if maxResults > 0 && stats.Results >= maxResults {
					return false
				}
			}
			return true
		}

		for page := 1; ; page++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Pick an API key
			apiKey := subscraping.PickRandom(apiKeys, s.Name())
			if apiKey == "" {
				stats.Skipped = true
				return
			}

			apiURL := fmt.Sprintf("https://api.whoisfreaks.com/v1.0/subdomains?apiKey=%s&domain=%s&status=active&page=%d",
				url.QueryEscape(apiKey), url.QueryEscape(domain), page)

			stats.Requests++
			body, err := request(ctx, session, http.MethodGet, apiURL, nil, nil, apiKey, url.QueryEscape(apiKey))
			if err != nil {
				fail(err)
				return
			}

			var data subdomainsResponse
			if err := json.Unmarshal(body, &data); err != nil {
				fail(err)
				return
			}
			if !data.Status {
				fail(fmt.Errorf("whoisfreaks: %s", data.Message))
				return
			}

			for _, item := range data.Subdomains {
				if !emit(item.Subdomain) {
					return
				}
			}

			// Stop once the last page has been consumed or nothing more was returned.
			if len(data.Subdomains) == 0 || page >= data.TotalPages {
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
	return "whoisfreaks"
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
