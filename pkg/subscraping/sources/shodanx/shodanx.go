// Package shodanx logic
package shodanx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

var (
	subdomainsBlockRegex = regexp.MustCompile(`(?s)<ul id="subdomains">(.*?)</ul>`)
	subdomainItemRegex   = regexp.MustCompile(`<li[^>]*>([^<]+)</li>`)
)

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
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://www.shodan.io/domain/%s", domain))
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

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			return
		}

		block := subdomainsBlockRegex.FindSubmatch(body)
		if block == nil {
			return
		}

		for _, match := range subdomainItemRegex.FindAllSubmatch(block[1], -1) {
			label := strings.TrimSpace(string(match[1]))
			if label == "" {
				continue
			}

			for _, subdomain := range session.Extractor.Extract(label + "." + domain) {
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
	return "shodanx"
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
