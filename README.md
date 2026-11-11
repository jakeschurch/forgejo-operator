# forgejo-operator

A Kubernetes operator for declaratively managing Forgejo organizations,
repositories, teams, robot accounts, credentials, webhooks, mirrors, and
protections.

The API is `forgejo.jakeschurch.com/v1alpha1`. Resources are namespaced,
credentials are read only from same-namespace Secrets, and deletion defaults to
`Orphan`. `ForgejoGPGKey` also defaults to `Orphan`; opt into `Delete` to remove
its managed remote public keys on deletion. See [docs/api-contract.md](docs/api-contract.md).

## Development

Requires Go 1.26.

```sh
go test ./...
go run ./cmd/manager
helm lint charts/forgejo-operator
nix flake check
```

Releases use SemVer tags (`v0.x.y`). Images are published to
`harbor.oci-registry.svc.cluster.local/foundry/forgejo-operator`.

Licensed under Apache-2.0.
