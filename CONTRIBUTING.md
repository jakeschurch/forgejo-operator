# Contributing

Open an issue before changing the public API. Run `go test ./...`,
`go vet ./...`, and `helm lint charts/forgejo-operator` before submitting a
change. Generated CRDs and RBAC must be committed with API changes. Releases
follow semantic versioning; the API remains alpha until adoption, deletion, and
credential lifecycle behavior have integration coverage against Forgejo 15.
