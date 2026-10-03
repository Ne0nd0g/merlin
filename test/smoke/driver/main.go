// Command driver is the gRPC half of the Merlin end-to-end smoke test. The surrounding run.sh
// starts a Merlin server; this program then, for each supported HTTP transport, creates a
// listener, launches the agent against it, waits for the agent to register, and runs commands,
// asserting each job reaches status "Complete".
//
//   - transports exercised: HTTP, H2C (clear-text) and HTTPS, HTTP2, HTTP3 (TLS; self-signed
//     cert generated here, agent dials with -secure=false so it skips verification).
//   - on the clear-text HTTP transport it also runs upload + download jobs; the upload is
//     content-verified (agent writes to a local path this process then reads).
//
// Exit code 0 means every transport passed; non-zero means at least one failed.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type transport struct {
	name       string // display name
	protocol   string // listener "Protocol" option
	agentProto string // agent -proto value
	scheme     string // URL scheme the agent dials
	port       string
	tls        bool
}

var transports = []transport{
	{"HTTP", "HTTP", "http", "http", "18080", false},
	{"H2C", "H2C", "h2c", "http", "18082", false},
	{"HTTPS", "HTTPS", "https", "https", "18443", true},
	{"HTTP2", "HTTP2", "h2", "https", "18444", true},
	{"HTTP3", "HTTP3", "http3", "https", "18445", true},
}

var (
	client   pb.MerlinClient
	agentBin string
	lhost    string
	psk      string
	workdir  string
	perTO    time.Duration
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "Merlin server gRPC address")
	password := flag.String("password", "merlin", "RPC client password")
	flag.StringVar(&agentBin, "agent", "", "path to the compiled merlin agent binary")
	flag.StringVar(&lhost, "lhost", "127.0.0.1", "listener interface")
	flag.StringVar(&psk, "psk", "merlin", "listener/agent pre-shared key")
	flag.StringVar(&workdir, "workdir", "", "scratch dir for certs and upload/download files (default: temp)")
	flag.DurationVar(&perTO, "timeout", 60*time.Second, "per-transport timeout")
	flag.Parse()

	if agentBin == "" {
		exit("the -agent flag (path to the agent binary) is required")
	}
	if workdir == "" {
		workdir, _ = os.MkdirTemp("", "merlin-smoke-")
	}

	// Mirror the CLI: always dial TLS (server serves a self-signed cert) and attach the password
	// as "authorization" metadata on every call.
	unary := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(metadata.AppendToOutgoingContext(ctx, "authorization", *password), method, req, reply, cc, opts...)
	}
	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})), // #nosec G402 - local self-signed server
		grpc.WithUnaryInterceptor(unary),
	)
	if err != nil {
		exit("dial %s: %s", *addr, err)
	}
	defer conn.Close()
	client = pb.NewMerlinClient(conn)

	certPath, keyPath, err := genSelfSigned(workdir)
	if err != nil {
		exit("generate TLS cert: %s", err)
	}

	fmt.Printf("Running %d transports (per-transport timeout %s)\n", len(transports), perTO)
	failures := 0
	for _, t := range transports {
		fmt.Printf("\n--- transport %s (listener=%s agent=-proto %s %s://) ---\n", t.name, t.protocol, t.agentProto, t.scheme)
		if err := runTransport(t, certPath, keyPath); err != nil {
			fmt.Printf("  FAIL %s: %s\n", t.name, err)
			failures++
		} else {
			fmt.Printf("  PASS %s\n", t.name)
		}
	}

	fmt.Printf("\n==== %d/%d transports passed ====\n", len(transports)-failures, len(transports))
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Println("SMOKE TEST PASSED \u2714")
}

func runTransport(t transport, certPath, keyPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), perTO)
	defer cancel()

	// Build listener options from the server defaults, then override for this transport.
	def, err := client.GetListenerDefaultOptions(ctx, &pb.String{Data: "http"})
	if err != nil {
		return fmt.Errorf("GetListenerDefaultOptions: %w", err)
	}
	o := def.GetOptions()
	if o == nil {
		o = map[string]string{}
	}
	o["Protocol"] = t.protocol
	o["Interface"] = lhost
	o["Port"] = t.port
	o["PSK"] = psk
	if t.tls {
		o["X509Cert"] = certPath
		o["X509Key"] = keyPath
	}

	preL := idSet(listenerIDs(ctx))
	if _, err = client.CreateListener(ctx, &pb.Options{Options: o}); err != nil {
		return fmt.Errorf("CreateListener: %w", err)
	}
	lid := firstNew(listenerIDs(ctx), preL)
	if lid == "" {
		return fmt.Errorf("no new listener id after CreateListener")
	}
	if _, err = client.StartListener(ctx, &pb.ID{Id: lid}); err != nil {
		step("StartListener note: %s (continuing)", err)
	}
	defer func() {
		dctx, dc := context.WithTimeout(context.Background(), 5*time.Second)
		defer dc()
		_, _ = client.StopListener(dctx, &pb.ID{Id: lid})
		_, _ = client.RemoveListener(dctx, &pb.ID{Id: lid})
	}()

	// Launch the agent.
	preA := idSet(agentIDs(ctx))
	url := fmt.Sprintf("%s://%s:%s/", t.scheme, lhost, t.port)
	logPath := filepath.Join(workdir, "agent-"+strings.ToLower(t.name)+".log")
	alog, _ := os.Create(logPath)
	step("launching agent -> %s (log: %s)", url, logPath)
	agent := exec.Command(agentBin, "-url", url, "-psk", psk, "-proto", t.agentProto, "-secure", "false", "-sleep", "1s") // #nosec G204 - local test binary
	if alog != nil {
		agent.Stdout, agent.Stderr = alog, alog
	}
	if err = agent.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	defer func() { _ = agent.Process.Kill() }()

	agentID := waitFor(ctx, func() (string, bool) {
		for _, id := range agentIDs(ctx) {
			if !preA[id] {
				return id, true
			}
		}
		return "", false
	})
	if agentID == "" {
		return fmt.Errorf("agent never registered (see %s)", logPath)
	}
	step("agent registered: %s", agentID)

	// PWD on every transport.
	if err = runJob(ctx, "pwd", agentID, func() (*pb.Message, error) {
		return client.PWD(ctx, &pb.ID{Id: agentID})
	}); err != nil {
		return err
	}

	// upload + download only on the clear-text HTTP transport (keeps the matrix fast).
	if t.name == "HTTP" {
		if err = uploadTest(ctx, agentID); err != nil {
			return err
		}
		if err = downloadTest(ctx, agentID); err != nil {
			return err
		}
	}
	return nil
}

// uploadTest sends known content to a local destination path and verifies the agent wrote it.
func uploadTest(ctx context.Context, agentID string) error {
	content := fmt.Sprintf("merlin-smoke-upload-%d", time.Now().UnixNano())
	dest := filepath.Join(workdir, "upload-dest.txt")
	_ = os.Remove(dest)
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	if err := runJob(ctx, "upload", agentID, func() (*pb.Message, error) {
		return client.Upload(ctx, &pb.AgentCMD{ID: agentID, Arguments: []string{b64, dest}})
	}); err != nil {
		return err
	}
	got, err := os.ReadFile(dest) // #nosec G304 - path we created under workdir
	if err != nil {
		return fmt.Errorf("upload: reading agent-written file %s: %w", dest, err)
	}
	if string(got) != content {
		return fmt.Errorf("upload: content mismatch: got %q want %q", string(got), content)
	}
	step("upload verified: %s", dest)
	return nil
}

// downloadTest asks the agent to return a local file; success is the job completing.
func downloadTest(ctx context.Context, agentID string) error {
	src := filepath.Join(workdir, "download-src.txt")
	if err := os.WriteFile(src, []byte("merlin-smoke-download"), 0o600); err != nil {
		return fmt.Errorf("download: writing source: %w", err)
	}
	if err := runJob(ctx, "download", agentID, func() (*pb.Message, error) {
		return client.Download(ctx, &pb.AgentCMD{ID: agentID, Arguments: []string{src}})
	}); err != nil {
		return err
	}
	step("download completed: %s", src)
	return nil
}

// runJob issues an RPC that queues a job, parses the returned job ID, and waits for it to complete.
func runJob(ctx context.Context, label, agentID string, issue func() (*pb.Message, error)) error {
	resp, err := issue()
	if err != nil {
		return fmt.Errorf("%s rpc: %w", label, err)
	}
	if resp.GetError() {
		return fmt.Errorf("%s rejected: %s", label, resp.GetMessage())
	}
	jobID := parseJobID(resp.GetMessage())
	if jobID == "" {
		return fmt.Errorf("%s: cannot parse job id from %q", label, resp.GetMessage())
	}
	ok := waitFor(ctx, func() (string, bool) {
		if jobComplete(ctx, jobID) {
			return "ok", true
		}
		return "", false
	})
	if ok == "" {
		return fmt.Errorf("%s job %s did not complete within %s", label, jobID, perTO)
	}
	step("%s completed (job %s)", label, jobID)
	return nil
}

func jobComplete(ctx context.Context, jobID string) bool {
	jobs, err := client.GetAllJobs(ctx, &emptypb.Empty{})
	if err != nil {
		return false
	}
	for _, j := range jobs.GetJobs() {
		if j.GetID() != jobID {
			continue
		}
		st := j.GetStatus()
		return j.GetCompleted() != "" || strings.EqualFold(st, "complete") || strings.EqualFold(st, "returned")
	}
	return false
}

// parseJobID extracts <id> from "Created job <id> for agent ...".
func parseJobID(msg string) string {
	if f := strings.Fields(msg); len(f) >= 3 && f[0] == "Created" && f[1] == "job" {
		return f[2]
	}
	return ""
}

func listenerIDs(ctx context.Context) []string {
	s, err := client.GetListenerIDs(ctx, &emptypb.Empty{})
	if err != nil {
		return nil
	}
	return s.GetData()
}

func agentIDs(ctx context.Context) []string {
	s, err := client.GetAgents(ctx, &emptypb.Empty{})
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

// waitFor polls fn every 500ms until it returns true or ctx expires.
func waitFor(ctx context.Context, fn func() (string, bool)) string {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		if v, ok := fn(); ok {
			return v
		}
		select {
		case <-ctx.Done():
			return ""
		case <-t.C:
		}
	}
}

// genSelfSigned writes a self-signed ECDSA cert + key (PEM) into dir and returns their paths.
func genSelfSigned(dir string) (certPath, keyPath string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "merlin-smoke"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, "smoke.crt")
	keyPath = filepath.Join(dir, "smoke.key")
	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	defer certOut.Close()
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	defer keyOut.Close()
	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func step(format string, a ...any) { fmt.Printf("  \u2022 "+format+"\n", a...) }

func exit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "SMOKE TEST ERROR: "+format+"\n", a...)
	os.Exit(1)
}
