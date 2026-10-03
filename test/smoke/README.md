# Merlin end-to-end smoke test

A black-box regression gate for the whole agent↔server round-trip. Because Merlin has few unit
tests, this is the primary "did a dependency bump break anything?" check.

## Run

```bash
./test/smoke/run.sh
```

Assumes the `merlin-agent` repo is a sibling of this one (`../merlin-agent`). Override paths/addr
with env vars: `MERLIN`, `AGENT`, `ADDR`, `PASSWORD`, `TIMEOUT`.

## What it does

`run.sh` builds the server + agent from the local workspace, starts the server headless, then runs
the gRPC driver (`driver/`, part of the `merlin` module — no separate go.mod). For each transport
it creates a listener, launches the agent against it, waits for the agent to register, and runs a
`pwd` job, asserting the job reaches status `Complete`:

| Transport | Listener `Protocol` | Agent `-proto` | Scheme |
|-----------|---------------------|----------------|--------|
| HTTP      | `HTTP`              | `http`         | http   |
| H2C       | `H2C`               | `h2c`          | http   |
| HTTPS     | `HTTPS`             | `https`        | https  |
| HTTP2     | `HTTP2`             | `h2`           | https  |
| HTTP3     | `HTTP3`             | `http3`        | https  |

TLS transports use a self-signed cert the driver generates; the agent dials with `-secure=false`.
On the clear-text HTTP transport it also runs `upload` (content-verified — the agent writes a file
this process reads back) and `download`. Exit 0 means every transport passed.

## Notes for maintainers

- The gRPC server always serves TLS (self-signed); clients dial TLS with `InsecureSkipVerify` when
  not in secure mode. Auth is an `authorization: <password>` metadata header on every call.
- Job status strings: `Created` → `Sent` → `Returned` → `Complete`.
- `GetAgentJobs` is currently unimplemented on the server; the driver uses `GetAllJobs` + filter.
