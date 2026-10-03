# AGENTS.md — merlin (server)

Guidance for AI coding agents working in this repo. Human contributors may find it useful too.

## What this is

The **Merlin C2 server**. Go module `github.com/Ne0nd0g/merlin/v2` (note the `/v2`). It owns the
gRPC contract at [`pkg/rpc/rpc.proto`](pkg/rpc/rpc.proto) that the `merlin-cli` client is generated
from. Operators drive the server with `merlin-cli` over gRPC; agents connect over HTTP listeners.

Target Go: **1.27** (revival target; drop the stale `toolchain` directive). Builds clean on Go 1.26.

## Build / run / test

```bash
go build ./...                 # build everything
go build -o merlinServer .     # build the server binary
go vet ./...
go test ./...                  # few tests exist; see the smoke test below
./merlinServer -addr 127.0.0.1:50051 -password <pw>   # run headless (TLS gRPC, self-signed)
```

End-to-end regression gate (the real safety net, since unit tests are sparse):

```bash
./test/smoke/run.sh            # builds server+agent, exercises all HTTP transports + up/download
```

## gRPC / runtime facts (non-obvious — learned the hard way)

- The gRPC server **always serves TLS** with a self-signed cert generated on boot. The `-secure`
  flag only toggles *client-certificate* verification; clients still dial TLS (CLI uses
  `InsecureSkipVerify` when not secure).
- Auth = an `authorization: <password>` **metadata header** on every gRPC call (default pw `merlin`).
- HTTP listener `Protocol` option values: `HTTP`, `HTTPS`, `HTTP2`, `H2C`, `HTTP3`. Clear-text
  listeners need no cert; TLS ones require real `X509Cert`/`X509Key` files (no auto-gen — see
  `pkg/servers/http/tls.go`). Default listener/agent PSK is `merlin`.
- Job status strings: `Created` → `Sent` → `Returned` → `Complete` (note: "Complete", not "Completed").
- **Known gap:** some RPCs in `rpc.proto` are not implemented and return gRPC `Unimplemented`
  (e.g. `GetAgentJobs`). Use `GetAllJobs` and filter by agent ID. Worth auditing the
  proto-vs-implemented surface during the revival.

## Cross-repo dependencies (release order matters)

```
merlin-message (base, stable v1.3.0) ──> merlin (this repo) ──(rpc.proto)──> merlin-cli
```

`merlin-message` is imported directly. The CLI is **not** a Go import — it is generated from this
repo's `rpc.proto`, so after changing the proto, regenerate the CLI's stubs and keep grpc/protobuf
versions aligned across both. Release order: message → server → cli.

## Conventions

- **Branches:** do all work on `dev` (or a feature branch). **Never commit to `main`.**
- **Commits:** the maintainer signs every commit with a YubiKey. **Do not run `git commit`** —
  stage changes and propose a commit message for the maintainer to run. Do **not** add a
  `Co-Authored-By` trailer. PR descriptions may keep the "Generated with Claude Code" line.
- Match surrounding style; keep the GPLv3 license header on new Go files.
