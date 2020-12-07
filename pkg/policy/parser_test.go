package policy

import (
	"strings"
	"testing"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	definition := `
		policy "admin" {
			rules {
				*authorized($0) 
					<- namespace(#ambient, $0)
					@  prefix($0, "demo.v1")
			}
			caveats {
				[*caveat0($0) <- authorized($0)]
			}
		}
		
		policy "developer" {
			rules {
				*authorized("demo.v1.Account", $1) 
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, $1),
						arg(#ambient, "env", $2)
					@	$1 in ["Create", "Read", "Update"],
						$2 in ["DEV", "STAGING"]
				*authorized("demo.v1.Account", "Read")
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, "Read"),
						arg(#ambient, "env", "PROD")
			}
			caveats {
				[*caveat1($1) <- authorized("demo.v1.Account", $1)]
			}
		}
		
		policy "auditor" {
			rules {
				*authorized("demo.v1.Account", "Read")
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, "Read"),
						arg(#ambient, "env", "DEV")
			}
			caveats {
				[*caveat2("Read") <- authorized("demo.v1.Account", "Read")]
			}
		}
	`

	policies, err := Parse(strings.NewReader(definition))
	require.NoError(t, err)

	expectedPolicies := map[string]Policy{
		"admin": {
			Name: "admin",
			Rules: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.Variable("0")}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable("0")}},
					},
					Constraints: []biscuit.Constraint{
						{Name: biscuit.Variable("0"), Checker: biscuit.StringComparisonChecker{Comparison: datalog.StringComparisonPrefix, Str: "demo.v1"}},
					},
				},
			},
			Caveats: []biscuit.Caveat{{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "caveat0", IDs: []biscuit.Atom{biscuit.Variable("0")}},
					Body: []biscuit.Predicate{
						{Name: "authorized", IDs: []biscuit.Atom{biscuit.Variable("0")}},
					},
					Constraints: []biscuit.Constraint{},
				},
			}}},
		},
		"developer": {
			Name: "developer",
			Rules: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.Variable("1")}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("demo.v1.Account")}},
						{Name: "method", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable("1")}},
						{Name: "arg", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("env"), biscuit.Variable("2")}},
					},
					Constraints: []biscuit.Constraint{
						{Name: biscuit.Variable("1"), Checker: biscuit.StringInChecker{Set: map[biscuit.String]struct{}{"Create": {}, "Read": {}, "Update": {}}}},
						{Name: biscuit.Variable("2"), Checker: biscuit.StringInChecker{Set: map[biscuit.String]struct{}{"DEV": {}, "STAGING": {}}}},
					},
				},
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.String("Read")}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("demo.v1.Account")}},
						{Name: "method", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("Read")}},
						{Name: "arg", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("env"), biscuit.String("PROD")}},
					},
					Constraints: []biscuit.Constraint{},
				},
			},
			Caveats: []biscuit.Caveat{{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "caveat1", IDs: []biscuit.Atom{biscuit.Variable("1")}},
					Body: []biscuit.Predicate{
						{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.Variable("1")}},
					},
					Constraints: []biscuit.Constraint{},
				},
			}}},
		},
		"auditor": {
			Name: "auditor",
			Rules: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.String("Read")}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("demo.v1.Account")}},
						{Name: "method", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("Read")}},
						{Name: "arg", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("env"), biscuit.String("DEV")}},
					},
					Constraints: []biscuit.Constraint{},
				},
			},
			Caveats: []biscuit.Caveat{{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "caveat2", IDs: []biscuit.Atom{biscuit.String("Read")}},
					Body: []biscuit.Predicate{
						{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.String("Read")}},
					},
					Constraints: []biscuit.Constraint{},
				},
			}}},
		},
	}

	require.Equal(t, expectedPolicies, policies)
}
