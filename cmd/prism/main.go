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
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES
var url = "https://127.0.0.1:443"
var psk = "merlin"
var proxy = ""
var secret []byte
var verbose = false
var debug = false
var JWT string

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	protocol := flag.String("proto", "h2", "Protocol for the agent to connect with [h2, hq]")
	flag.StringVar(&proxy, "proxy", proxy, "Hardcoded proxy to use for http/1.1 traffic only that will override host configuration")
	flag.Usage = usage
	flag.Parse()

	var err error

	// Setup and run agent
	a, errNew := agent.New(*protocol, url, psk, proxy, verbose, debug)
	if errNew != nil {
		message("warn", errNew.Error())
		os.Exit(1)
	}

	k := sha256.Sum256([]byte(psk))
	secret = k[:]

	// Set initial JWT
	JWT, err = getJWT(a.ID)
	if err != nil {
		message("warn", err.Error())
		os.Exit(1)
	}

	// Check for v0.7.0 or earlier
	message("info", fmt.Sprintf("Connecting to %s checking for Merlin server version v0.7.0.BETA or earlier", url))
	err = sendPre8Message(a)
	if err != nil {
		if verbose {
			message("warn", err.Error())
		}
		message("note", fmt.Sprintf("%s is not a Merlin server", url))
	} else {
		os.Exit(0)
	}

	// Send message to server and see if I get a AuthInit message that I can decrypt
	message("info", fmt.Sprintf("Connecting to %s checking for Merlin server version v0.8.0.BETA or greater", url))
	err = opaqueAuthenticate(a)
	if err != nil {
		if verbose {
			message("warn", err.Error())
		}
		message("note", fmt.Sprintf("%s is not a Merlin server using \"%s\" as a pre-shared key", url, psk))
	}
}

// opaqueAuthenticate is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func opaqueAuthenticate(a agent.Agent) error {
	// 1 - Create a NewUserAuth with an embedded key exchange
	userKex := gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	userAuth := gopaque.NewUserAuth(gopaque.CryptoDefault, a.ID.Bytes(), userKex)

	// 2 - Call Init with the password and send the resulting UserAuthInit to the server
	userAuthInit, err := userAuth.Init([]byte(psk))
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
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	authInitResp, errAuthInitResp := sendMessage("POST", authInitBase, a.Client)

	if errAuthInitResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication initialization message:\r\n%s", errAuthInitResp.Error())
	}

	if authInitResp.Type != "AuthInit" {
		return fmt.Errorf("invalid message type %s in resopnse to OPAQUE user authenticaion initialization", authInitResp.Type)
	}

	// If we get this far then it means we sent a message to the server encrypted with the correct psk and it responded
	message("success", fmt.Sprintf("Verified Merlin server v0.8.0.BETA or greater instance at %s", url))

	if verbose {
		message("note", fmt.Sprintf("Decrypted Merlin message:\r\n%+v", authInitResp))
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
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// Save the OPAQUE derived Diffie-Hellman secret
	secret = []byte(userKex.SharedSecret.String())

	if verbose {
		message("note", fmt.Sprintf("Session encryption key for %s: %v", a.ID, secret))
	}

	// Send the User Auth Complete message
	authCompleteResp, errAuthCompleteResp := sendMessage("POST", authCompleteBase, a.Client)

	if errAuthCompleteResp != nil {
		return fmt.Errorf("there was an error sending the agent OPAQUE authentication completion message:\r\n%s", errAuthCompleteResp.Error())
	}

	switch authCompleteResp.Type {
	case "ServerOk":
		if verbose {
			message("success", "Agent authentication successful")
			message("note", fmt.Sprintf("Decrypted Merlin message:\r\n%+v", authCompleteResp))
		}
		if debug {
			message("debug", "Leaving agent.opaqueAuthenticate without error")
		}
		return nil
	default:
		return fmt.Errorf("recieved unexpected or unrecognized message type during OPAQUE authentication completion:\r\n%s", authCompleteResp.Type)
	}

}

func sendPre8Message(a agent.Agent) error {
	g := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "StatusCheckIn",
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
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
	resp, err := a.Client.Do(req)

	if err != nil {
		return fmt.Errorf("there was an error sending the request:\r\n%s", err.Error())
	}

	var payload json.RawMessage
	j := messages.Base{
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
		return fmt.Errorf("recieved JSON message did not contain an message type of AgentControl")
	}
	return nil
}

// sendMessage is a generic function to receive a messages.Base struct, encode it, encrypt it, and send it to the server
// The response message will be decrypted, decoded, and return a messages.Base struct.
func sendMessage(method string, m messages.Base, client *http.Client) (messages.Base, error) {
	if debug {
		message("debug", "Entering into agent.sendMessage")
	}
	if verbose {
		message("note", fmt.Sprintf("Sending %s message to %s", m.Type, url))
	}

	var returnMessage messages.Base

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		return returnMessage, fmt.Errorf("there was an error encoding the %s message to a gob:\r\n%s", m.Type, errGobEncode.Error())
	}

	// Get JWE
	jweString, errJWE := core.GetJWESymetric(messageBytes.Bytes(), secret)
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
		req, reqErr := http.NewRequest("POST", url, jweBytes)
		if reqErr != nil {
			return returnMessage, fmt.Errorf("there was an error building the HTTP request:\r\n%s", reqErr.Error())
		}

		if req != nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 ")
			req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", JWT))
		}

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			return returnMessage, fmt.Errorf("there was an error with the HTTP client while performing a POST:\r\n%s", err.Error())
		}
		if debug {
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
		respMessage, errDecrypt := core.DecryptJWE(jweString, secret)
		if errDecrypt != nil {
			return returnMessage, errDecrypt
		}

		return respMessage, nil
	default:
		return returnMessage, fmt.Errorf("%s is an invalid method for sending a message", method)
	}

}

// getJWT is used to send an unauthenticated JWT on the first message to the server
func getJWT(agentID uuid.UUID) (string, error) {
	// Create encrypter
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT, // Doesn't create a per message key
			Key:       secret},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWT encryptor:\r\n%s", encErr.Error())
	}

	// Create signer
	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       secret},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	// Build JWT claims
	cl := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       agentID.String(),
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
