// Package racent logic
package racent

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// maxPages caps the number of result pages requested per domain.
const maxPages = 5

type racentResponse struct {
	Code int `json:"code"`
	Data struct {
		TotalPages int `json:"total_pages"`
		List       []struct {
			DNSNames []string `json:"dnsnames"`
		} `json:"list"`
	} `json:"data"`
}

// Source is the passive scraping agent
type Source struct {
	mu    sync.Mutex
	stats subscraping.Statistics
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		emit := func(subdomain string) bool {
			select {
			case <-ctx.Done():
				return false
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				stats.Results++
				return session.MaxResults == 0 || stats.Results < session.MaxResults
			}
		}

		totalPages := 1
		for page := 1; page <= totalPages && page <= maxPages; page++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			stats.Requests++
			data, err := s.fetchPage(ctx, session, domain, page)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			if data.Code != 0 {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("racent: API returned code %d", data.Code)}
				stats.Errors++
				return
			}

			totalPages = data.Data.TotalPages
			if len(data.Data.List) == 0 {
				return
			}

			for _, entry := range data.Data.List {
				for _, name := range entry.DNSNames {
					for _, subdomain := range session.Extractor.Extract(name) {
						if !emit(subdomain) {
							return
						}
					}
				}
			}
		}
	}()

	return results
}

// fetchPage retrieves and decodes a single page of results.
func (s *Source) fetchPage(ctx context.Context, session *subscraping.Session, domain string, page int) (*racentResponse, error) {
	resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://face.racent.com/tool/query_ctlog?keyword=%s&page=%d&limit=100", domain, page))
	defer session.DiscardHTTPResponse(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var data racentResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "racent"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
