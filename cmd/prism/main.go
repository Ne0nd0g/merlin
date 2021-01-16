/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2019  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	// Standard
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent"
	merlinHTTP "github.com/Ne0nd0g/merlin/pkg/agent/clients/http"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// GLOBAL VARIABLES
var url = "https://127.0.0.1:443"
var psk = "merlin"
var proxy = ""
var verbose = false
var debug = false
var host string
var ja3 = ""
var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 "

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	protocol := flag.String("proto", "h2", "Protocol for the agent to connect with [https (HTTP/1.1), h2 (HTTP/2), hq (QUIC or HTTP/3.0)]")
	flag.StringVar(&proxy, "proxy", proxy, "Hardcoded proxy to use for http/1.1 traffic only that will override host configuration")
	flag.StringVar(&host, "host", host, "HTTP Host header")
	flag.StringVar(&ja3, "ja3", ja3, "JA3 signature string (not the MD5 hash). Overrides -proto flag")
	flag.Usage = usage
	flag.Parse()

	var err error

	// Setup and run agent
	agentConfig := agent.Config{
		Sleep:    "30s",
		Skew:     "3000",
		KillDate: "0",
		MaxRetry: "7",
	}
	a, errNew := agent.New(agentConfig)
	if errNew != nil {
		message("warn", errNew.Error())
		os.Exit(1)
	}

	// Get the client
	var errClient error
	clientConfig := merlinHTTP.Config{
		AgentID:     a.ID,
		Protocol:    *protocol,
		Host:        host,
		URL:         url,
		Proxy:       proxy,
		UserAgent:   useragent,
		PSK:         psk,
		JA3:         ja3,
		Padding:     "0",
		AuthPackage: "opaque",
	}
	a.Client, errClient = merlinHTTP.New(clientConfig)
	if errClient != nil {
		if verbose {
			color.Red(errClient.Error())
		}
	}

	// Check for v0.7.0 or earlier
	message("info", fmt.Sprintf("Connecting to %s checking for Merlin server version v0.7.0.BETA or earlier", url))
	err = sendPre8Message(*a)
	if err != nil {
		if verbose {
			message("warn", err.Error())
		}
		message("note", fmt.Sprintf("%s is not a Merlin server", url))
	} else {
		os.Exit(0)
	}

	// Send message to server and see if I get a RegInit message that can be decrypted
	message("info", fmt.Sprintf("Connecting to %s checking for Merlin server version v0.8.0.BETA or greater", url))
	err = opaqueRegister(*a)
	if err != nil {
		if verbose {
			message("warn", err.Error())
		}
		message("note", fmt.Sprintf("%s is not a Merlin server using \"%s\" as a pre-shared key", url, psk))
	}
}

// opaqueAuthenticate is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func opaqueRegister(a agent.Agent) error {

	// message to be sent to the server
	regInitBase := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    messages.OPAQUE,
	}
	o, _, err := opaque.UserRegisterInit(a.ID)
	if err != nil {
		return err
	}
	regInitBase.Payload = o

	regInitResp, errRegInitResp := a.Client.SendMerlinMessage(regInitBase)

	if errRegInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE user registration initialization message:\r\n%s", errRegInitResp.Error())
	}

	if regInitResp.Type != messages.OPAQUE {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user registration initialization", messages.String(regInitResp.Type))
	}

	// If we get this far then it means we sent a message to the server encrypted with the correct psk and it responded
	message("success", fmt.Sprintf("Verified Merlin server v0.8.0.BETA or greater instance at %s", url))

	if verbose {
		message("note", fmt.Sprintf("Decrypted Merlin message:\r\n%+v", regInitResp))
	}

	var serverRegInit gopaque.ServerRegisterInit

	errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload.([]byte))
	if errServerRegInit != nil {
		return fmt.Errorf("there was an error unmarshalling the OPAQUE server register initialization message from bytes:\r\n%s", errServerRegInit.Error())
	}

	if verbose {
		message("info", fmt.Sprintf("OPAQUE Beta:\t\t%s", serverRegInit.Beta))
		message("info", fmt.Sprintf("OPAQUE V:\t\t%s", serverRegInit.V))
		message("info", fmt.Sprintf("OPAQUE PubS:\t\t%s", serverRegInit.ServerPublicKey))
	}

	return nil
}

func sendPre8Message(a agent.Agent) error {
	g := oldBase{
		Version: 1.0,
		ID:      a.ID,
		Type:    "StatusCheckIn",
		Padding: core.RandStringBytesMaskImprSrc(10),
	}

	b := new(bytes.Buffer)
	errJ := json.NewEncoder(b).Encode(g)
	if errJ != nil {
		return fmt.Errorf("there was an error encoding the JSON message:\r\n%s", errJ.Error())
	}

	req, reqErr := http.NewRequest("POST", url, b)
	if reqErr != nil {
		return fmt.Errorf("there was an error creating a new HTTP request:\r\n%s", reqErr)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 ")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return fmt.Errorf("there was an error sending the request:\r\n%s", err.Error())
	}

	var payload json.RawMessage
	j := oldBase{
		Payload: &payload,
	}

	errDecode := json.NewDecoder(resp.Body).Decode(&j)
	if errDecode != nil {
		return fmt.Errorf("there was an error decoding the message response into a JSON message:\r\n%s", errDecode.Error())
	}

	if j.Type == "AgentControl" {
		message("success", fmt.Sprintf("Verified Merlin server v0.7.0.BETA or earlier instance at %s", url))
		if verbose {
			message("note", fmt.Sprintf("Merlin message:\r\n%+v", j))
		}
	} else {
		return fmt.Errorf("received JSON message did not contain an message type of AgentControl")
	}
	return nil
}

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

// usage prints command line options
func usage() {
	fmt.Printf("Merlin PRISM\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}

type oldBase struct {
	Version float32     `json:"version"`
	ID      uuid.UUID   `json:"id"`
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
	Padding string      `json:"padding"`
	Token   string      `json:"token,omitempty"`
}
