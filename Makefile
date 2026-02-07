.PHONY: build build-grpc run run-grpc test tidy fmt clean

NAME = proxy-relay
COMMIT = $(shell git rev-parse --short HEAD)
TAG = $(shell git describe --tags --always)
VERSION = $(TAG:v%=%)

GO ?= go
BINARY ?= relay
CMD ?= ./cmd/relay
TAGS ?= with_acme
LDFLAGS ?=

PARAMS = -v -trimpath -ldflags "-X 'github.com/AkinoKaede/proxy-relay/pkg/constant.Version=$(VERSION)' -s -w -buildid= $(LDFLAGS)"

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
	$(GO) fmt ./...

clean:
	rm -rf $(BIN_DIR)
