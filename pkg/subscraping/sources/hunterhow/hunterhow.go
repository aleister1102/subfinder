// Package hunterhow logic
package hunterhow

import (
	"context"
	"encoding/base64"
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

// pageSize is the number of records requested per page.
const pageSize = 100

// searchResponse is the JSON payload returned by the search endpoint.
type searchResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		List  []struct {
			Domain string `json:"domain"`
		} `json:"list"`
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

		// Hunter.how expects a base64 URL-safe encoded FOFA-style query over the last year.
		query := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`domain.suffix="%s"`, domain)))
		now := time.Now().UTC()
		startDate := now.AddDate(-1, 0, 0).Format("2006-01-02")
		endDate := now.Format("2006-01-02")

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

		fetched := 0
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

			apiURL := fmt.Sprintf("https://api.hunter.how/search?api-key=%s&query=%s&start_time=%s&end_time=%s&page=%d&page_size=%d",
				url.QueryEscape(apiKey), url.QueryEscape(query), startDate, endDate, page, pageSize)

			stats.Requests++
			body, err := request(ctx, session, http.MethodGet, apiURL, nil, nil, apiKey, url.QueryEscape(apiKey))
			if err != nil {
				fail(err)
				return
			}

			var data searchResponse
			if err := json.Unmarshal(body, &data); err != nil {
				fail(err)
				return
			}
			if data.Code != http.StatusOK {
				fail(fmt.Errorf("hunterhow: code %d: %s", data.Code, data.Message))
				return
			}
			if len(data.Data.List) == 0 {
				return
			}

			for _, item := range data.Data.List {
				if !emit(item.Domain) {
					return
				}
			}

			// Stop once every reported record has been fetched.
			fetched += len(data.Data.List)
			if fetched >= data.Data.Total {
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
	return "hunterhow"
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
