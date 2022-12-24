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
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	messageAPI "github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/services/handle/listener"
)

// handler contains contextual information and methods to process HTTP traffic for Agents
type handler struct {
	jwtKey   []byte // The password used by the server to create JWTs
	listener uuid.UUID
	psk      []byte // The Pre-Shared Key that the listener was created with; Unauthenticated agent's encrypt their JWT with this
}

// agentHandler implements the HTTP Handler interface and processes HTTP traffic for agents
// HTTP validation checks are performed here such as JSON Web Token authentication, HTTP headers, HTTP methods, and User-Agent
// The actual HTTP payload data that contains the Agent message is not handled here. It is sent to the listener service to process
func (h *handler) agentHandler(w http.ResponseWriter, r *http.Request) {
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
	agentID, code := h.checkJWT(r)
	if code != 0 {
		w.WriteHeader(code)
		return
	}

	//Read the request message until EOF
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		m := fmt.Sprintf("There was an error reading a POST message sent by an agent:\r\n%s", err)
		message("warn", m)
		logging.Server(m)
		return
	}

	lhs, err := listener.NewListenerHandlerService(h.listener)
	if err != nil {
		m := fmt.Sprintf("There was an error getting a new listener handler service: %s", err)
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(500)
		return
	}

	// Handle the incoming data
	rdata, err := lhs.Handle(agentID, data)
	if err != nil {
		m := fmt.Sprintf("There was an error handling the incoming data: %s", err)
		message("warn", m)
		logging.Server(m)
		w.WriteHeader(500)
		return
	}

	// Set return headers
	w.Header().Set("Content-Type", "application/octet-stream")
	n, err := w.Write(rdata)
	if err != nil {
		m := fmt.Sprintf("there was an error writing the HTTP response bytes: %s", err)
		message("warn", m)
		logging.Server(m)
		return
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Wrote %d bytes to HTTP response", n))
	}

}

// checkJWT ensures that the incoming message has an Authorization header with a Bearer token.
// It then tries to decrypt the incoming JWT with the HTTP interface's key used only with authenticated agents.
// If that fails, it will try to decrypt the incoming JWT with the HTTP interface's PSK used only with unauthenticated agents.
// After the JWT is decrypted, its claims are validated.
func (h *handler) checkJWT(request *http.Request) (agentID uuid.UUID, code int) {
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
	agentID, err = ValidateJWT(jwt, h.jwtKey)
	// If agentID was returned, then message contained a JWT encrypted with the HTTP interface key
	// Else the message is from an unauthenticated agent encrypted with the listener's PSK
	if err != nil && agentID == uuid.Nil {
		if core.Verbose {
			message("warn", err.Error())
			message("note", "Authorization JWT not signed with server's interface key, trying again with PSK...")
		}
		// Validate JWT using interface PSK; Used by unauthenticated agents
		hashedKey := sha256.Sum256(h.psk)
		key := hashedKey[:]
		agentID, err = ValidateJWT(jwt, key)
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
