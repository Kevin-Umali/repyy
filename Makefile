BINARY := bin/repyy
VERSION ?= 0.8.0

.PHONY: build test check bench security intel install clean site-dev site-check site-build site-preview site-format

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/repyy

test:
	go test -race -shuffle=on ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race -shuffle=on ./...

# Fixture recall, benign controls, and high findings on pinned clean repositories.
bench: build
	python3 scripts/hard_benchmark/run.py --binary $(BINARY) --work .bench fixtures noise --check --min-detected 58

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

intel:
	go run ./cmd/repyy-intelgen

install:
	go install -trimpath -ldflags "-s -w -X main.version=$(VERSION)" ./cmd/repyy

clean:
	rm -f $(BINARY)

site-dev:
	npm --prefix site run dev

site-check:
	npm --prefix site run check

site-build:
	npm --prefix site run build

site-preview:
	npm --prefix site run preview

site-format:
	npm --prefix site run format

# Generated reports and inert test fixtures retain their exact bytes.
.PHONY: format format-check
format:
	gofmt -w cmd internal test
	npx --yes prettier@3.7.4 --write . --ignore-unknown
	uvx ruff==0.16.0 format scripts site/check_docs.py
	go run mvdan.cc/sh/v3/cmd/shfmt@v3.12.0 -w -i 2 scripts/*.sh

format-check:
	test -z "$$(gofmt -l cmd internal test)"
	npx --yes prettier@3.7.4 --check . --ignore-unknown
	uvx ruff==0.16.0 format --check scripts site/check_docs.py
	go run mvdan.cc/sh/v3/cmd/shfmt@v3.12.0 -d -i 2 scripts/*.sh
