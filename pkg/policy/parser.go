package policy

import (
	"fmt"
	"io"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/parser"
)

type Policy struct {
	Name    string
	Rules   []biscuit.Rule
	Caveats []biscuit.Caveat
}

var defaultParserOptions = append(parser.DefaultParserOptions, participle.Lexer(policyLexer))

var policyLexer = stateful.MustSimple(append(
	parser.BiscuitLexerRules,
	stateful.Rule{"Policy", `policy`, nil},
))

type Document struct {
	Policies []*DocumentPolicy `@@*`
}

type DocumentPolicy struct {
	Comments []string         `@Comment*`
	Name     *string          `"policy"  @String "{"`
	Rules    []*parser.Rule   `("rules" "{" @@* "}")?`
	Caveats  []*parser.Caveat `("caveats" "{" (@@ ("," @@+)*)* "}")? "}"`
}

func (d *DocumentPolicy) ToPolicy() (*Policy, error) {
	rules := make([]biscuit.Rule, 0, len(d.Rules))
	for _, r := range d.Rules {
		rule, err := r.ToBiscuit()
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)
	}

	caveats := make([]biscuit.Caveat, 0, len(d.Caveats))
	for _, c := range d.Caveats {
		caveat, err := c.ToBiscuit()
		if err != nil {
			return nil, err
		}

		caveats = append(caveats, *caveat)
	}

	return &Policy{
		Name:    *d.Name,
		Rules:   rules,
		Caveats: caveats,
	}, nil
}

var documentParser = participle.MustBuild(&Document{}, defaultParserOptions...)

func Parse(r io.Reader) (map[string]Policy, error) {
	parsed := &Document{}
	if err := documentParser.Parse("policy", r, parsed); err != nil {
		return nil, err
	}

	policies := make(map[string]Policy, len(parsed.Policies))
	for _, p := range parsed.Policies {
		if _, exists := policies[*p.Name]; exists {
			return nil, fmt.Errorf("parse error: duplicate policy %q", *p.Name)
		}
		policy, err := p.ToPolicy()
		if err != nil {
			return nil, err
		}
		policies[*p.Name] = *policy
	}

	return policies, nil
}
