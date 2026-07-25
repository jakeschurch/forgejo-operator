.PHONY: generate test verify
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
