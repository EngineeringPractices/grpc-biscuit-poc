

# Examples

**Check all policies for a call to demo.api.v1.Demo.Read for the `DEV` env:**

```
go run cmd/checker/checker.go -c demo-v1-Demo.policy -f 'service(#ambient, "demo.api.v1.Demo")' -f 'method(#ambient, "Read")' -f 'arg(#ambient, "env", "DEV")'
```

Produces:

```
Loaded 4 policies from demo-v1-Demo.policy
Testing policy "auditor"
- Biscuit verification succeeded
- Query result for "*arg($0, $1) <- arg(#ambient, $0, $1)":
[
        arg("env", "DEV")
]
Testing policy "admin"
- Biscuit verification succeeded
- Query result for "*arg($0, $1) <- arg(#ambient, $0, $1)":
[
        arg("env", "DEV")
]
Testing policy "developer"
- Biscuit verification succeeded
- Query result for "*arg($0, $1) <- arg(#ambient, $0, $1)":
[
        arg("env", "DEV")
]
Testing policy "guest"
- ERROR: biscuit: verification failed: failed to verify block #0 caveat #0: *authorized($0) <- allow_method(#authority, $0)
- Query result for "*arg($0, $1) <- arg(#ambient, $0, $1)":
[
        arg("env", "DEV")
]
```

**Check only `guest` policy for a call to demo.api.v1.Demo.Read for the `DEV` env:**

```
go run cmd/checker/checker.go -c demo-v1-Demo.policy -f 'method(#ambient, "Read")' -f 'service(#ambient, "demo.api.v1.Demo")' -f 'arg(#ambient, "env", "DEV")' -p guest
```

Produces:

```
Loaded 4 policies from demo-v1-Demo.policy
Testing policy "guest"
- ERROR: biscuit: verification failed: failed to verify block #0 caveat #0: *authorized($0) <- allow_method(#authority, $0)
```

**Run a query to list all allow_method facts for all policies:**

```
go run cmd/checker/checker.go -c demo-v1-Demo.policy -f 'method(#ambient, "Read")' -f 'service(#ambient, "demo.api.v1.Demo")' -f 'arg(#ambient, "env", "DEV")' -r '*allowed_method($0) <- allow_method(#authority, $0)'
```

Produces:

```
Loaded 4 policies from demo-v1-Demo.policy
Testing policy "admin"
- Biscuit verification succeeded
- Query result for "*allowed_method($0) <- allow_method(#authority, $0)":
[
        allowed_method("Read")
]
Testing policy "developer"
- Biscuit verification succeeded
- Query result for "*allowed_method($0) <- allow_method(#authority, $0)":
[
        allowed_method("Read")
]
Testing policy "guest"
- ERROR: biscuit: verification failed: failed to verify block #0 caveat #0: *authorized($0) <- allow_method(#authority, $0)
- Query result for "*allowed_method($0) <- allow_method(#authority, $0)":
[]
Testing policy "auditor"
- Biscuit verification succeeded
- Query result for "*allowed_method($0) <- allow_method(#authority, $0)":
[]
```
