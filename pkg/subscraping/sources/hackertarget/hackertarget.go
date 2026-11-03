// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"fmt"
	"slices"
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

		// Bail out fast when the host is blocked or unreachable.
		if err := session.Preflight(ctx, "https://hackertarget.com/"); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("hackertarget preflight failed (blocked/unreachable): %w", err)}
			stats.Errors++
			return
		}

		htSearchUrl := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey != "" {
			htSearchUrl = fmt.Sprintf("%s&apikey=%s", htSearchUrl, randomApiKey)
		}

		stats.Requests++
		resp, err := session.SimpleGet(ctx, htSearchUrl)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
			}
		}()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			// A plaintext quota or error line comes back with HTTP 200.
			if isQuotaError(line) {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("hackertarget blocked: %s", line)}
				stats.Errors++
				return
			}
			match := session.Extractor.Extract(line)
			for _, subdomain := range match {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
			}
		}
	}()

	return results
}

// isQuotaError reports whether a response line is a plaintext error that
// hackertarget returns with HTTP 200 when the quota is used up.
func isQuotaError(line string) bool {
	return strings.Contains(line, "API count exceeded") || strings.HasPrefix(line, "error ")
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.OptionalKey
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
