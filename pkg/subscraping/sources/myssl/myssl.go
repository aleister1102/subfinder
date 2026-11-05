// Package myssl logic
package myssl

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type mysslResponse struct {
	Code int `json:"code"`
	Data []struct {
		Domain string `json:"domain"`
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

		stats.Requests++
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://myssl.com/api/v1/discover_sub_domain?domain=%s", domain))
		defer session.DiscardHTTPResponse(resp)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			return
		}

		if resp.StatusCode != http.StatusOK {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code %d", resp.StatusCode)}
			stats.Errors++
			return
		}

		var data mysslResponse
		if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			return
		}

		if data.Code != 0 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("myssl: API returned code %d", data.Code)}
			stats.Errors++
			return
		}

		for _, record := range data.Data {
			for _, subdomain := range session.Extractor.Extract(record.Domain) {
				if !emit(subdomain) {
					return
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "myssl"
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
