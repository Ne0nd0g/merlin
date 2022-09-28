// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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
	"encoding/gob"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/handlers"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	messageAPI "github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	messages2 "github.com/Ne0nd0g/merlin/pkg/handlers/messages"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/util"
)

// HTTPContext contains contextual information about a handler such as secrets for encrypt/decrypt
type HTTPContext struct {
	handlers.Context
	PSK       string       // The pre-shared key password used prior to Password Authenticated Key Exchange (PAKE)
	JWTKey    []byte       // The password used by the server to create JWTs
	OpaqueKey kyber.Scalar // OPAQUE server's keys
}

// AgentHTTP function is responsible for all Merlin agent traffic
func (ctx *HTTPContext) AgentHTTP(w http.ResponseWriter, r *http.Request) {
	if core.Verbose {
		m := fmt.Sprintf("Received %s %s connection from %s", r.Proto, r.Method, r.RemoteAddr)
		message("warn", m)
		logging.Server(m)
	}

	if core.Debug {
		var m string
		m += "HTTP Connection Details:\r\n"
		m += fmt.Sprintf("Host: %s\r\n", r.Host)
		m += fmt.Sprintf("URI: %s\r\n", r.RequestURI)
		m += fmt.Sprintf("Method: %s\r\n", r.Method)
		m += fmt.Sprintf("Protocol: %s\r\n", r.Proto)
		m += fmt.Sprintf("Headers: %s\r\n", r.Header)
		if r.TLS != nil {
			m += fmt.Sprintf("TLS Negotiated Protocol: %s\r\n", r.TLS.NegotiatedProtocol)
			m += fmt.Sprintf("TLS Cipher Suite: %d\r\n", r.TLS.CipherSuite)
			m += fmt.Sprintf("TLS Server Name: %s\r\n", r.TLS.ServerName)
		}
		m += fmt.Sprintf("Content Length: %d", r.ContentLength)

		message("debug", m)
		logging.Server(m)
	}

	// Merlin only accepts/handles HTTP POST messages
	if r.Method != http.MethodPost {
		w.WriteHeader(404)
		return
	}

	// Check for Merlin PRISM activity
	if r.UserAgent() == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 " {
		m := fmt.Sprintf("Someone from %s is attempting to fingerprint this Merlin server", r.RemoteAddr)
		message("warn", m)
		logging.Server(m)
	}

	// Make sure the content type is: application/octet-stream; charset=utf-8
	if r.Header.Get("Content-Type") != "application/octet-stream; charset=utf-8" {
		if core.Verbose {
			m := "incoming request did not contain a Content-Type header of: application/octet-stream; charset=utf-8"
			message("warn", m)
			logging.Server(m)
		}
		w.WriteHeader(404)
		return
	}

	// Determine if the JWT was encrypted with the HTTP interface key or the interface/agent PSK
	agentID, code := ctx.checkJWT(r)
	if code != 0 {
		w.WriteHeader(code)
		return
	}

	//Read the request message until EOF
	requestBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		m := fmt.Sprintf("There was an error reading a POST message sent by an agent:\r\n%s", err)
		message("warn", m)
		logging.Server(m)
		return
	}

	// Gob decode the HTTP payload body, a JWE string
	var jweString string
	errDecode := gob.NewDecoder(bytes.NewReader(requestBytes)).Decode(&jweString)
	if errDecode != nil {
		message("warn", fmt.Sprintf("there was an error decoding JWE payload message sent by an agent:\r\n%s", errDecode.Error()))
		return
	}

	// Determine which key the JWE should have been encrypted with
	var key []byte
	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent doesn't exist, so it's first message must be encrypted with the PSK
		hashedKey := sha256.Sum256([]byte(ctx.PSK))
		key = hashedKey[:]
	} else {
		if len(agent.Secret) > 0 {
			key = agent.Secret
		} else {
			hashedKey := sha256.Sum256([]byte(ctx.PSK))
			key = hashedKey[:]
		}
	}

	// Decrypt the JWE
	var msg messages.Base
	msg, err = util.DecryptJWE(jweString, key)
	if err != nil {
		var m string
		// Land here when agent was obfuscated with Garble and obfuscated structures don't match
		// Fix is to Garble BOTH the server AND the agent with the same seed
		// gob: type mismatch: no fields matched compiling decoder for Base
		if strings.Contains(err.Error(), "gob: type mismatch:") {
			m = fmt.Sprintf("recieved gob encoding error: %s\n", err)
			m += "ensure BOTH the Merlin server AND agent were both garbled with the SAME seed"
		} else {
			m = fmt.Sprintf("there was an error decrypting the JWE string with the PSK for agent %s: %s", agentID, err)
		}
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(404)
		return
	}

	if core.Verbose {
		message("info", fmt.Sprintf("Received %s message from %s at %s", messages.String(msg.Type), msg.ID, time.Now().UTC().Format(time.RFC3339)))
	}
	if core.Debug {
		message("debug", fmt.Sprintf("POST DATA: %+v", msg))
	}

	// Verify JWT ID matches Merlin message ID
	if agentID != msg.ID || msg.ID == uuid.Nil {
		m := fmt.Sprintf("Received a message with JWT Agent ID of %s but a Merlin message ID of %s. Returning 404", agentID, msg.ID)
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(404)
		return
	}

	// Send decoded and decrypted Base message into the handler
	err = messages2.In(msg)
	if err != nil {
		message("warn", err.Error())
		logging.Server(err.Error())
		w.WriteHeader(404)
		return
	}

	// Build and return a Base message for this agent
	var returnMessage messages.Base
	returnMessage, err = messages2.Out(agentID)
	if err != nil {
		message("warn", err.Error())
		logging.Server(err.Error())
		w.WriteHeader(404)
		return
	}

	if core.Verbose {
		message("note", fmt.Sprintf("Sending %s message type to agent %s", messages.String(returnMessage.Type), agentID))
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Sending message to agent:\r\n%+v", returnMessage))
	}

	// Get JWT to add to message.Base for all messages except re-authenticate messages
	// OPAQUE_RE_AUTH
	if returnMessage.Type != messages.OPAQUE {
		jsonWebToken, errJWT := util.GetJWT(agentID, ctx.JWTKey)
		if errJWT != nil {
			message("warn", errJWT.Error())
			w.WriteHeader(404)
			return
		}
		returnMessage.Token = jsonWebToken
	}

	// Gob encode the return Base message
	returnMessageBytes := new(bytes.Buffer)
	err = gob.NewEncoder(returnMessageBytes).Encode(returnMessage)
	if err != nil {
		m := fmt.Sprintf("there was an error encoding the %s return message for agent %s into a GOB:\r\n%s", messages.String(returnMessage.Type), agentID, err.Error())
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(404)
		return
	}

	// The agent should exist and its secret should be updated
	agent, ok = agents.Agents[agentID]
	if !ok {
		m := fmt.Sprintf("unable to get agent %s's encryption key because it does not exist", agentID)
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(404)
	}
	if agent.Authenticated {
		key = agent.Secret
	}

	// Encrypt the Base message into a JWE string
	jwe, err := core.GetJWESymetric(returnMessageBytes.Bytes(), key)
	if err != nil {
		message("warn", err.Error())
		logging.Server(err.Error())
		w.WriteHeader(404)
		return
	}

	// Set return headers
	w.Header().Set("Content-Type", "application/octet-stream")

	// TODO Can I remove this second round of Gob encoding? Seems unnecessary
	// Gob encode the JWE and write it to HTTP response stream
	err = gob.NewEncoder(w).Encode(jwe)
	if err != nil {
		m := fmt.Sprintf("there was an error Gob encoding the return JWE for agent %s: %s", agentID, err)
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(404)
		return
	}

	// TODO this can't stay here because it won't account for delegate messages
	// Agent can't be removed until after the JWE key is obtained to encrypt the message
	if returnMessage.Type == messages.JOBS {
		for _, job := range returnMessage.Payload.([]jobs.Job) {
			if job.Type == jobs.CONTROL {
				if strings.ToLower(job.Payload.(jobs.Command).Command) == "exit" {
					err := agents.RemoveAgent(job.AgentID)
					if err != nil {
						message("warn", err.Error())
					} else {
						message("info", fmt.Sprintf("Agent %s was removed from the server at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
					}
				}
			}
		}
	}

	if core.Debug {
		message("debug", "Leaving http2.agentHandler function without error")
	}
}

// checkJWT ensures that the incoming message has an Authorization header with a Bearer token.
// It then tries to decrypt the incoming JWT with the HTTP interface's key used only with authenticated agents.
// If that fails, it will try to decrypt the incoming JWT with the HTTP interface's PSK used only with unauthenticated agents.
// After the JWT is decrypted, its claims are validated.
func (ctx *HTTPContext) checkJWT(request *http.Request) (agentID uuid.UUID, code int) {
	// Make sure the message has a JWT
	token := request.Header.Get("Authorization")
	if token == "" {
		code = 404
		if core.Verbose {
			m := "incoming request did not contain an Authorization header"
			message("warn", m)
			logging.Server(m)
		}
		return
	}

	// Make sure the Authorization header contains a bearer token
	if !strings.Contains(token, "Bearer eyJ") {
		code = 404
		if core.Verbose {
			m := "incoming request did not contain a Bearer token"
			message("warn", m)
			logging.Server(m)
		}
		return
	}

	jwt := strings.Split(token, " ")[1]

	// Validate JWT using HTTP interface JWT key; Given to authenticated agents by server
	if core.Verbose {
		message("note", "Checking to see if authorization JWT was signed by server's interface key...")
	}

	var err error
	agentID, err = util.ValidateJWT(jwt, ctx.JWTKey)
	// If agentID was returned, then message contained a JWT encrypted with the HTTP interface key
	// Else the message is from an unauthenticated agent encrypted with the interface PSK
	if err != nil && agentID == uuid.Nil {
		if core.Verbose {
			message("warn", err.Error())
			message("note", "Authorization JWT not signed with server's interface key, trying again with PSK...")
		}
		// Validate JWT using interface PSK; Used by unauthenticated agents
		hashedKey := sha256.Sum256([]byte(ctx.PSK))
		key := hashedKey[:]
		agentID, err = util.ValidateJWT(jwt, key)
		if agentID != uuid.Nil {
			if core.Debug {
				message("info", fmt.Sprintf("UnAuthenticated JWT from %s", agentID))
			}
		}
	} else {
		if core.Debug {
			message("info", fmt.Sprintf("Authenticated JWT from %s", agentID))
		}
	}

	// Handle edge case situations
	if err != nil {
		// If both an agentID and error were returned, then the claims were likely bad and the agent needs to re-authenticate
		if agentID != uuid.Nil {
			m := fmt.Sprintf("Agent %s connected with expired JWT. Instructing agent to re-authenticate", agentID)
			message("note", m)
			logging.Server(m)
			code = 403
			return
		} else if len(token) == 402 && request.ContentLength > 390 {
			// Check to see if the request matches traffic that could be an orphaned agent
			// An orphaned agent will have a JWT encrypted with server's JWT key, not the PSK

			m := fmt.Sprintf("Orphaned agent request detected from %s, instructing agent to re-register and authenticate", request.RemoteAddr)
			message("note", m)
			logging.Server(m)
			code = 401
			return
		} else {
			code = 404
			if core.Verbose {
				message("note", "Authorization JWT not signed with PSK, returning 404...")
				message("warn", err.Error())
			}
			return
		}
	}
	return
}

// message is used to send a broadcast message to all connected clients
func message(level string, message string) {
	m := messageAPI.UserMessage{
		Message: message,
		Time:    time.Now().UTC(),
		Error:   false,
	}
	switch level {
	case "info":
		m.Level = messageAPI.Info
	case "note":
		m.Level = messageAPI.Note
	case "warn":
		m.Level = messageAPI.Warn
	case "debug":
		m.Level = messageAPI.Debug
	case "success":
		m.Level = messageAPI.Success
	default:
		m.Level = messageAPI.Plain
	}
	messageAPI.SendBroadcastMessage(m)
}
