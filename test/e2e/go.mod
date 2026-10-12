// Module merlin-e2e is a test-only module for Merlin end-to-end tests that need to
// drive more than one component at once (the server's operator gRPC API and the real
// merlin-agent client). It is intentionally a separate module so neither merlin's nor
// merlin-agent's shippable module gains a dependency on the other; the replace
// directives assume the sibling repos are checked out next to this one, matching the
// layout the test/smoke harness already relies on.
module github.com/Ne0nd0g/merlin/v2/test/e2e

go 1.27.2

require (
	github.com/Ne0nd0g/merlin-agent/v2 v2.0.0
	github.com/Ne0nd0g/merlin-message v1.4.0
	github.com/Ne0nd0g/merlin/v2 v2.0.0
	github.com/google/uuid v1.6.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/Ne0nd0g/winhttp v1.0.1 // indirect
	github.com/andybalholm/brotli v1.2.6 // indirect
	github.com/cretz/gopaque v0.1.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.5 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.63.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/kyber/v3 v3.1.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
)

replace github.com/Ne0nd0g/merlin/v2 => ../..

replace github.com/Ne0nd0g/merlin-agent/v2 => ../../../merlin-agent
