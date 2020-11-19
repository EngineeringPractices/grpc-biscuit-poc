# Biscuit GRPC POC

**/!\ Requires WIP features on biscuit-go, its version in go.mod file point to a tmp branch merging them all**

This repo provides utility packages:

- pkg/antireplay: a nonce store and nonce checker for signed biscuit anti replay checks 
- pkg/authorization: client and server GRPC interceptors 
    - the client interceptor is created from a base biscuit, and will attach a signed version to each outgoing requests
    - the server interceptor will validate the biscuit on each requests, injecting the called method and arguments as ambient fact on the verifier. It checks for signature validity, replay attempts, and authorization from the policy.
- pkg/pb: provides a demo GRPC service 
- pkg/policy: provide a parser for policy file (see also [demo-v1-Demo.policy](./demo-v1-Demo.policy) sample file)

And some binaries:

- cmd/client: a demo GRPC client testing the policy on various method / argument calls
- cmd/server: a demo GRPC server
- cmd/keys: a key generator creating the various key files needed for the demo
- cmd/checker: a policy checker tool (see the [Checker README](./cmd/checker/README.md))
