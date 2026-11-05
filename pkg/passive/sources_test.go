package passive

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	expectedAllSources = []string{
		"agniops",
		"alienvault",
		"anubis",
		"arquivopt",
		"bevigil",
		"builtwith",
		"c99",
		"censys",
		"certspotter",
		"chaos",
		"chinaz",
		"commoncrawl",
		"criminalip",
		"crtlive",
		"crtname",
		"crtsh",
		"digitalyama",
		"digitorus",
		"dnsdb",
		"dnsdumpster",
		"dnsrepo",
		"driftnet",
		"fofa",
		"fullhunt",
		"github",
		"hackertarget",
		"hudsonrock",
		"hunterhow",
		"intelx",
		"leakix",
		"merklemap",
		"myssl",
		"netlas",
		"onyphe",
		"profundis",
		"pugrecon",
		"pulsedive",
		"quake",
		"racent",
		"rapiddns",
		"reconeer",
		"reverseipdomain",
		"rsecloud",
		"scanmalware",
		"securitytrails",
		"shodan",
		"shodanct",
		"shodanx",
		"sitedossier",
		"subdomainapp",
		"subdomaincenter",
		"thc",
		"threatbook",
		"urlscan",
		"virustotal",
		"waybackarchive",
		"whoisfreaks",
		"whoisxmlapi",
		"windvane",
		"zoomeyeapi",
	}

	expectedDefaultSources = []string{
		"agniops",
		"alienvault",
		"anubis",
		"bevigil",
		"builtwith",
		"c99",
		"censys",
		"certspotter",
		"chaos",
		"chinaz",
		"crtlive",
		"crtname",
		"crtsh",
		"digitalyama",
		"digitorus",
		"dnsdumpster",
		"dnsrepo",
		"driftnet",
		"fofa",
		"fullhunt",
		"hackertarget",
		"intelx",
		"leakix",
		"myssl",
		"onyphe",
		"profundis",
		"pulsedive",
		"quake",
		"racent",
		"reconeer",
		"reverseipdomain",
		"rsecloud",
		"scanmalware",
		"securitytrails",
		"shodan",
		"shodanct",
		"shodanx",
		"subdomainapp",
		"subdomaincenter",
		"urlscan",
		"virustotal",
		"whoisxmlapi",
		"windvane",
	}

	expectedDefaultRecursiveSources = []string{
		"agniops",
		"alienvault",
		"certspotter",
		"crtlive",
		"crtsh",
		"digitorus",
		"dnsdb",
		"driftnet",
		"hackertarget",
		"leakix",
		"merklemap",
		"pulsedive",
		"scanmalware",
		"securitytrails",
		"shodanct",
		"subdomainapp",
		"subdomaincenter",
		"urlscan",
		"virustotal",
	}
)

func TestSourceCategorization(t *testing.T) {
	defaultSources := make([]string, 0, len(AllSources))
	recursiveSources := make([]string, 0, len(AllSources))
	for _, source := range AllSources {
		sourceName := source.Name()
		if source.IsDefault() {
			defaultSources = append(defaultSources, sourceName)
		}

		if source.HasRecursiveSupport() {
			recursiveSources = append(recursiveSources, sourceName)
		}
	}

	assert.ElementsMatch(t, expectedDefaultSources, defaultSources)
	assert.ElementsMatch(t, expectedDefaultRecursiveSources, recursiveSources)
	assert.ElementsMatch(t, expectedAllSources, slices.Collect(maps.Keys(NameSourceMap)))
}

// Review: not sure if this test is necessary/useful
// implementation is straightforward where sources are stored in maps and filtered based on options
// the test is just checking if the filtering works as expected using count of sources
func TestSourceFiltering(t *testing.T) {
	someSources := []string{
		"alienvault",
		"chaos",
		"crtname",
		"crtsh",
		"virustotal",
	}

	someExclusions := []string{
		"alienvault",
		"virustotal",
	}

	tests := []struct {
		sources        []string
		exclusions     []string
		withAllSources bool
		withRecursion  bool
		expectedLength int
	}{
		{someSources, someExclusions, false, false, len(someSources) - len(someExclusions)},
		{someSources, someExclusions, false, true, 1},
		{someSources, someExclusions, true, false, len(AllSources) - len(someExclusions)},

		{someSources, []string{}, false, false, len(someSources)},
		{someSources, []string{}, true, false, len(AllSources)},

		{[]string{}, []string{}, false, false, len(expectedDefaultSources)},
		{[]string{}, []string{}, true, false, len(AllSources)},
		{[]string{}, []string{}, true, true, len(expectedDefaultRecursiveSources)},
	}
	for index, test := range tests {
		t.Run(strconv.Itoa(index+1), func(t *testing.T) {
			agent := New(test.sources, test.exclusions, test.withAllSources, test.withRecursion)

			for _, v := range agent.sources {
				fmt.Println(v.Name())
			}

			assert.Equal(t, test.expectedLength, len(agent.sources))
			agent = nil
		})
	}
}
