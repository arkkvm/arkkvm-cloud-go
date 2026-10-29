VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint run docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/arkkvm-cloud ./cmd/server

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

run: build
	ARK_ENV_MODE=testing ./bin/arkkvm-cloud

docker:
	docker build -f deployments/Dockerfile --build-arg VERSION=$(VERSION) -t arkkvm-cloud:$(VERSION) .

clean:
	rm -rf bin/
