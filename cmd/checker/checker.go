package main

import (
	"crypto/rand"
	"demo/pkg/policy"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/parser"
	"github.com/flynn/biscuit-go/sig"
)

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, "\n")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, strings.TrimSpace(value))
	return nil
}

func main() {
	log.SetFlags(0)

	var cfg, policyName, rule string
	var facts stringSliceFlag
	flag.StringVar(&cfg, "c", "", "a policy definition file")
	flag.StringVar(&policyName, "p", "", "restrict the check to a policy name, default will check all policies")
	flag.Var(&facts, "f", "repeatable, fact added to the verifier")
	flag.StringVar(&rule, "r", "", "a rule to query the verifier with and print results")
	flag.Parse()

	if cfg == "" {
		log.Fatalf("-c is required")
	}

	definitions, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatalf("failed to load definitions: %v", err)
	}

	policies, err := policy.Parse(string(definitions))
	if err != nil {
		log.Fatalf("failed to parse definition: %v", err)
	}
	log.Printf("Loaded %d policies from %s", len(policies), cfg)

	testedPolicies := policies
	if policyName != "" {
		p, ok := policies[policyName]
		if !ok {
			log.Fatalf("no policy named %q found in config", policyName)
		}
		testedPolicies = map[string]policy.Policy{policyName: p}
	}

	for _, policy := range testedPolicies {
		log.Printf("Testing policy %q", policy.Name)
		v, err := getVerifier(policy)
		if err != nil {
			log.Fatalf("failed to get verifier: %v", err)
		}

		p := parser.New()

		if len(facts) > 0 {
			for _, f := range facts {
				fact, err := p.Fact(f)
				if err != nil {
					log.Fatalf("failed to parse fact %q: %v", f, err)
				}
				v.AddFact(fact)
			}
			if err := v.Verify(); err != nil {
				log.Printf("- ERROR: %v", err)
			} else {
				log.Println("- Biscuit verification succeeded")
			}
		}

		if rule != "" {
			r, err := p.Rule(rule)
			if err != nil {
				log.Fatalf("failed to parse rule %q: %v", rule, err)
			}
			res, err := v.Query(r)
			if err != nil {
				log.Fatalf("query failed: %v", err)
			}

			log.Printf("- Query result for %q:\n%s", rule, res)
		}
	}
}

func getVerifier(policy policy.Policy) (biscuit.Verifier, error) {
	rootKey := sig.GenerateKeypair(rand.Reader)
	builder := biscuit.NewBuilder(rand.Reader, rootKey)
	for _, r := range policy.Rules {
		if err := builder.AddAuthorityRule(r); err != nil {
			return nil, fmt.Errorf("failed to add rule %q: %v", r, err)
		}
	}
	for _, c := range policy.Caveats {
		if err := builder.AddAuthorityCaveat(c); err != nil {
			return nil, fmt.Errorf("failed to add caveat %q: %v", c, err)
		}
	}

	bisc, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %v", err)
	}
	verifier, err := bisc.Verify(rootKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %v", err)
	}

	return verifier, nil
}
