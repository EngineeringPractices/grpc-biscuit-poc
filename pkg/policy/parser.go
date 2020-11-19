package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"github.com/flynn/biscuit-go"
	biscuitParser "github.com/flynn/biscuit-go/parser"
)

type Policy struct {
	Name    string
	Rules   []biscuit.Rule
	Caveats []biscuit.Caveat
}

var defaultParserOptions = []participle.Option{
	participle.Lexer(lexer.DefaultDefinition),
	participle.UseLookahead(3),
}

type document struct {
	Policies []*documentPolicy `@@+`
}

type documentPolicy struct {
	Name    string                  `"policy" @String "{"`
	Rules   []*biscuitParser.Rule   `"rules" "{" @@* "}"`
	Caveats []*biscuitParser.Caveat `"caveats" "{" @@* "}" "}"`
}

func (d *documentPolicy) ToPolicy() (*Policy, error) {
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
		Name:    d.Name,
		Rules:   rules,
		Caveats: caveats,
	}, nil
}

var documentParser = participle.MustBuild(&document{}, defaultParserOptions...)

func Parse(definition string) (map[string]Policy, error) {
	var err error
	definition, err = replaceNamedVariables(definition)
	if err != nil {
		return nil, err
	}

	parsed := &document{}
	if err := documentParser.ParseString(definition, parsed); err != nil {
		return nil, err
	}

	policies := make(map[string]Policy, len(parsed.Policies))
	for _, p := range parsed.Policies {
		if _, exists := policies[p.Name]; exists {
			return nil, fmt.Errorf("parse error: duplicate policy %q", p.Name)
		}
		policy, err := p.ToPolicy()
		if err != nil {
			return nil, err
		}
		policies[p.Name] = *policy
	}

	return policies, nil
}

var variableRE = regexp.MustCompile(`\$[0-9]+`)
var namedVariableRE = regexp.MustCompile(`\$[a-zA-Z][a-zA-Z0-9]+`)

// replaceNamedVariables returns the definition, with all named variable replaced
// with their integer counterpart, suitable for biscuit.
// All variables with the same name will be affected the same integer
func replaceNamedVariables(definition string) (string, error) {
	regularVariables := variableRE.FindAllString(definition, -1)
	namedVariables := namedVariableRE.FindAllString(definition, -1)
	replaced := definition

	existingVariables := make(map[int]struct{})
	for _, rv := range regularVariables {
		i, err := strconv.ParseInt(strings.Replace(rv, "$", "", 1), 10, 32)
		if err != nil {
			return "", err
		}
		existingVariables[int(i)] = struct{}{}
	}

	vars := make(map[string]struct{})
	var lastID int
	for _, namedVar := range namedVariables {
		if _, exists := vars[namedVar]; !exists {
			variableID := lastID
			// keep incrementing variableID until it does not overlap an existing variable
			for {
				if _, exists := existingVariables[variableID]; !exists {
					break
				}
				variableID++
			}

			replaced = strings.ReplaceAll(replaced, namedVar, fmt.Sprintf("$%d", variableID))
			vars[namedVar] = struct{}{}
			lastID = variableID + 1
		}
	}

	return replaced, nil
}
