.PHONY: build build-grpc run run-grpc test tidy fmt clean

GO ?= go
BINARY ?= relay
CMD ?= ./cmd/relay
TAGS ?= with_acme
LDFLAGS ?=

build:
	$(GO) build -tags "$(TAGS)" -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

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
