.PHONY: build build-grpc run run-grpc test tidy fmt clean

GO ?= go
BINARY ?= relay
CMD ?= ./cmd/relay
BIN_DIR ?= .
TAGS ?=
LDFLAGS ?=

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -tags "$(TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

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
