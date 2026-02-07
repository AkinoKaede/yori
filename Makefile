.PHONY: build build-grpc run run-grpc test tidy fmt fmt_install lint lint_install clean

NAME = yori
COMMIT = $(shell git rev-parse --short HEAD)
TAG = $(shell git describe --tags --always)
VERSION = $(TAG:v%=%)

GO ?= go
BINARY ?= yori
CMD ?= ./cmd/yori
TAGS ?= with_acme
LDFLAGS ?=

PARAMS = -v -trimpath -ldflags "-X 'github.com/AkinoKaede/yori/pkg/constant.Version=$(VERSION)' -s -w -buildid= $(LDFLAGS)"

build:
	$(GO) build $(PARAMS) -tags "$(TAGS)" -o $(BINARY) $(CMD)

build-grpc:
	$(MAKE) build TAGS="$(TAGS) with_grpc"

run:
	$(GO) run -tags "$(TAGS)" $(CMD)

run-grpc:
	$(GO) run -tags "$(TAGS) with_grpc" $(CMD)

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/AkinoKaede/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest

lint:
	GOOS=linux golangci-lint run ./...
	GOOS=android golangci-lint run ./...
	GOOS=windows golangci-lint run ./...
	GOOS=darwin golangci-lint run ./...
	GOOS=freebsd golangci-lint run ./...

lint_install:
	go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@latest

clean:
	rm -rf $(BIN_DIR)
