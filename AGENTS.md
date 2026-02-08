# Repository Guidelines

## Project Structure & Module Organization
- `cmd/yori/` is the main application entry point (`yori`).
- `internal/` holds core packages (config, engine, inbound/outbound, subscription, server, utils).
- `pkg/constant/` exposes shared constants used across packages.
- `subscription/` contains reusable subscription processing helpers.
- `config.example.yaml` documents configuration; `config.yaml` is local runtime config.
- `acme/`, `cache.db`, and `data.db` are runtime artifacts (certs/cache/state); avoid committing changes.

## Build, Test, and Development Commands
- `make build` builds the `yori` binary with ACME, QUIC and uTLS support (set `BINARY=...` to override output path).
- `make build-grpc` builds with gRPC support (`with_grpc` build tag).
- `make run` runs the app from source with ACME, QUIC and uTLS support (`with_acme with_quic with_utls` tags).
- `make run-grpc` runs with gRPC support.
- `make test` executes `go test ./...`.
- `make tidy` runs `go mod tidy`.
- `make fmt` formats code with `gofumpt`, `gofmt -s`, and `gci`.
- `make lint` runs `golangci-lint` across common GOOS targets.

## Coding Style & Naming Conventions
- Go code should be formatted with `make fmt`; tabs and `gofmt`-style layout are expected.
- Import order follows `gci`’s custom order (`standard`, `github.com/AkinoKaede/*`, `default`).
- Exported identifiers use `CamelCase`; unexported use `lowerCamelCase`.
- New files should include the GPL-3.0 header when required (see README).

## Testing Guidelines
- Tests live next to code as `*_test.go` files and use `TestXxx` naming.
- Run `make test` before opening a PR.
- If adding behavior without tests, explain why in the PR and keep scope minimal.

## Commit & Pull Request Guidelines
- Commit messages follow Conventional Commits patterns seen in history: `feat:`, `fix:`, `docs:`, `style:`, `chore:`.
- PRs should include: a short summary, relevant config or API changes, and the commands run (e.g., `make test`).
- Update `config.example.yaml` and README when configuration or behavior changes.

## Security & Configuration Tips
- Keep tokens and DNS credentials out of git; prefer environment variables in config values.
- Treat `config.yaml` as local-only and avoid committing secrets.
