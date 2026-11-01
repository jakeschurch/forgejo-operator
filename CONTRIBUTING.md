# Contributing

Open an issue before changing the public API. Run `go test ./...`,
`go vet ./...`, and `helm lint charts/forgejo-operator` before submitting a
change. Generated CRDs and RBAC must be committed with API changes. Releases
follow semantic versioning; the API remains alpha until adoption, deletion, and
credential lifecycle behavior have integration coverage against Forgejo 15.

`make integration` runs the access token lifecycle against a real Forgejo, started
from `FORGEJO_BIN`; without it those tests skip.
