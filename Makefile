.PHONY: test-fetch test-unit build test-integration test run

IMAGE ?= home-unbound:local

test-fetch:
	docker run --rm -v "$(CURDIR):/src:ro" -w /src \
		alpine:3.24.3 sh -ec 'apk add --no-cache ca-certificates curl gnupg >/dev/null && sh tests/fetch-unbound-test.sh'

test-unit:
	docker run --rm -v "$(CURDIR)/manager:/src" -w /src \
		-e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOFLAGS=-mod=mod \
		golang:1.27.3-alpine3.24 sh -c 'go vet ./... && go test ./...'

build:
	docker build -t "$(IMAGE)" .

test-integration:
	bash tests/integration.sh

test: test-fetch test-unit test-integration

run:
	docker compose up --build
