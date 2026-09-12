BINARY := bin/repyy
VERSION ?= 0.3.0-dev

.PHONY: build test check security intel install clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/repyy

test:
	go test -race ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

intel:
	go run ./cmd/repyy-intelgen

install:
	go install -trimpath -ldflags "-s -w -X main.version=$(VERSION)" ./cmd/repyy

clean:
	rm -f $(BINARY)
