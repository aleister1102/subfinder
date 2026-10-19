// Package crtlive logic
package crtlive

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
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

		stats.Requests++
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://crt.live/txt/%s", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		defer session.DiscardHTTPResponse(resp)

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// crt.live lines can be "*.sub.example.com" or "sub.example.com"
			line = strings.TrimPrefix(line, "*.")

			for _, subdomain := range session.Extractor.Extract(line) {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
					if session.MaxResults > 0 && stats.Results >= session.MaxResults {
						return
					}
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtlive"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return false
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
