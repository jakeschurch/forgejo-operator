.PHONY: generate test verify integration
generate:
	controller-gen object:headerFile=/dev/null paths=./api/...
	controller-gen crd paths=./api/... output:crd:artifacts:config=config/crd/bases
	cp config/crd/bases/*.yaml charts/forgejo-operator/crds/

test:
	go test ./...

verify: generate test
	go vet ./...
	helm lint charts/forgejo-operator
	helm template forgejo-operator charts/forgejo-operator >/dev/null

# Needs FORGEJO_BIN: the forgejo binary to run a throwaway instance from. The locked
# nixpkgs carries 15.0.5: nix build --inputs-from . nixpkgs#forgejo-lts
integration:
	go test ./internal/controller/ -run TestIntegration -count=1 -v
