package policy

import (
	"testing"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestReplaceNamedVariables(t *testing.T) {
	definitions := `
		*allow_method($method)
			<-	method(#ambient, $method), 
				arg(#ambient, "env", $env) 
			@ 	$method in ["Create", "Delete"], 
				$env == "DEV"
		*allow_method($method)
			<-	method(#ambient, $method),
				arg(#ambient, "env", $env)
			@ 	$method in ["Read", "Update"],
				$env in ["DEV", "STG"]
		*allow_method("Read")
			<- 	service(#ambient, "demo.api.v1.Demo"),
				method(#ambient, "Read"),
				arg(#ambient, "env", $env),
				arg(#ambient, "entities.name", $entityNames)
			@	$env == "PRD",
				$entityNames in ["entity1", "entity2", "entity3"]`

	expected := `
		*allow_method($0)
			<-	method(#ambient, $0), 
				arg(#ambient, "env", $1) 
			@ 	$0 in ["Create", "Delete"], 
				$1 == "DEV"
		*allow_method($0)
			<-	method(#ambient, $0),
				arg(#ambient, "env", $1)
			@ 	$0 in ["Read", "Update"],
				$1 in ["DEV", "STG"]
		*allow_method("Read")
			<- 	service(#ambient, "demo.api.v1.Demo"),
				method(#ambient, "Read"),
				arg(#ambient, "env", $1),
				arg(#ambient, "entities.name", $2)
			@	$1 == "PRD",
				$2 in ["entity1", "entity2", "entity3"]`

	replaced, err := replaceNamedVariables(definitions)
	require.NoError(t, err)
	require.Equal(t, expected, replaced)
}

func TestParse(t *testing.T) {
	definition := `
		policy "admin" {
			rules {
				*authorized($namespace) 
					<- namespace(#ambient, $namespace)
					@  prefix($namespace, "demo.v1")
			}
			caveats {
				[*caveat0($namespace) <- authorized($namespace)]
			}
		}
		
		policy "developer" {
			rules {
				*authorized("demo.v1.Account", $method) 
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, $method),
						arg(#ambient, "env", $env)
					@	$method in ["Create", "Read", "Update"],
						$env in ["DEV", "STAGING"]
				*authorized("demo.v1.Account", "Read")
					<- 	namespace(#ambient, "demo.v1.Account"),
						method(#ambient, "Read"),
						arg(#ambient, "env", "PROD")
			}
			caveats {
				[*caveat1($method) <- authorized("demo.v1.Account", $method)]
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

	policies, err := Parse(definition)
	require.NoError(t, err)

	expectedPolicies := map[string]Policy{
		"admin": {
			Name: "admin",
			Rules: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.Variable(0)}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(0)}},
					},
					Constraints: []biscuit.Constraint{
						{Name: biscuit.Variable(0), Checker: biscuit.StringComparisonChecker{Comparison: datalog.StringComparisonPrefix, Str: "demo.v1"}},
					},
				},
			},
			Caveats: []biscuit.Caveat{{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "caveat0", IDs: []biscuit.Atom{biscuit.Variable(0)}},
					Body: []biscuit.Predicate{
						{Name: "authorized", IDs: []biscuit.Atom{biscuit.Variable(0)}},
					},
					Constraints: []biscuit.Constraint{},
				},
			}}},
		},
		"developer": {
			Name: "developer",
			Rules: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.Variable(1)}},
					Body: []biscuit.Predicate{
						{Name: "namespace", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("demo.v1.Account")}},
						{Name: "method", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.Variable(1)}},
						{Name: "arg", IDs: []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String("env"), biscuit.Variable(2)}},
					},
					Constraints: []biscuit.Constraint{
						{Name: biscuit.Variable(1), Checker: biscuit.StringInChecker{Set: map[biscuit.String]struct{}{"Create": {}, "Read": {}, "Update": {}}}},
						{Name: biscuit.Variable(2), Checker: biscuit.StringInChecker{Set: map[biscuit.String]struct{}{"DEV": {}, "STAGING": {}}}},
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
					Head: biscuit.Predicate{Name: "caveat1", IDs: []biscuit.Atom{biscuit.Variable(1)}},
					Body: []biscuit.Predicate{
						{Name: "authorized", IDs: []biscuit.Atom{biscuit.String("demo.v1.Account"), biscuit.Variable(1)}},
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
