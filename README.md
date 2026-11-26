# forgejo-operator

A Kubernetes operator for declaratively managing Forgejo organizations,
repositories, teams, robot accounts, credentials, webhooks, mirrors, and
protections.

The API is `forgejo.jakeschurch.com/v1alpha1`. Resources are namespaced,
credentials are read only from same-namespace Secrets, and deletion defaults to
`Orphan`. `ForgejoGPGKey` also defaults to `Orphan`; opt into `Delete` to remove
its managed remote public keys on deletion. `ForgejoSSHKey` registers a user's
existing SSH (signing) public key; the owner proves possession once in the web
UI. See [docs/api-contract.md](docs/api-contract.md).

## Development

Requires Go 1.26.

```sh
go test ./...
go run ./cmd/manager
helm lint charts/forgejo-operator
nix flake check
```

Margo publishes releases from `main` to
`harbor.oci-registry.svc.cluster.local/foundry/forgejo-operator`. Published
images and their source commits use tags of the form
`forgejo-operator.main.<UTC timestamp>.<short commit SHA>`. A docs-only
change that leaves the image and deployment inputs unchanged retains the
previous tag and digest.

CI note: merge-queue probes stage the main image build on the trusted farm so
the following main build is a cache hit.

Licensed under Apache-2.0.
