/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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

package http

import (
	"context"
	// Standard
	"crypto/sha256"
	"fmt"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message"
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	message2 "github.com/Ne0nd0g/merlin/v2/pkg/services/message"
)

// Handler contains contextual information and methods to process HTTP traffic for Agents
type Handler struct {
	jwtKey    []byte        // The password used by the server to create JWTs
	jwtLeeway time.Duration // The amount of flexibility in validating the JWT's expiration time. Less than 0 will disable the expiration check
	listener  uuid.UUID
	psk       []byte // The Pre-Shared Key that the listener was created with; Unauthenticated agent's encrypt their JWT with this
}

// agentHandler implements the HTTP Handler interface and processes HTTP traffic for agents
// HTTP validation checks are performed here such as JSON Web Token authentication, HTTP headers, HTTP methods, and User-Agent
// The actual HTTP payload data that contains the Agent message is not handled here. It is sent to the listener service to process
func (h *Handler) agentHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("New HTTP connection", "protocol", r.Proto, "method", r.Method, "remote address", r.RemoteAddr)

	if r.TLS != nil {
		slog.Log(context.Background(), logging.LevelExtraDebug, "HTTP Connection Details",
			"host", r.Host,
			"uri", r.RequestURI,
			"method", r.Method,
			"protocol", r.Proto,
			"headers", r.Header,
			"content length", r.ContentLength,
			"tls negotiated protocol", r.TLS.NegotiatedProtocol,
			"tls cipher suite", r.TLS.CipherSuite,
			"tls server name", r.TLS.ServerName,
		)
	} else {
		slog.Log(context.Background(), logging.LevelExtraDebug, "HTTP Connection Details",
			"host", r.Host,
			"uri", r.RequestURI,
			"method", r.Method,
			"protocol", r.Proto,
			"headers", r.Header,
			"content length", r.ContentLength,
		)
	}

	// Merlin only accepts/handles HTTP POST messages
	if r.Method != http.MethodPost {
		w.WriteHeader(404)
		return
	}

	// Check for Merlin PRISM activity
	if r.UserAgent() == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 " {
		msg := fmt.Sprintf("Someone from %s is attempting to fingerprint this Merlin server", r.RemoteAddr)
		slog.Warn(msg)
	}

	// Make sure the content type is: application/octet-stream; charset=utf-8
	if r.Header.Get("Content-Type") != "application/octet-stream; charset=utf-8" {
		if core.Verbose {
			msg := "incoming request did not contain a Content-Type header of: application/octet-stream; charset=utf-8"
			slog.Warn(msg)
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
	data, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error(fmt.Sprintf("There was an error reading a POST message sent by an agent: %s", err))
		return
	}

	// Get service to handle Agent Base messages
	ms, err := message2.NewMessageService(h.listener)
	if err != nil {
		slog.Error(fmt.Sprintf("There was an error getting a new Base message service: %s", err))
		w.WriteHeader(500)
		return
	}

	// Handle the incoming data
	rdata, err := ms.Handle(agentID, data)
	if err != nil {
		slog.Error(fmt.Sprintf("There was an error handling the incoming data: %s", err))
		w.WriteHeader(500)
		return
	}

	// Set return headers
	w.Header().Set("Content-Type", "application/octet-stream")
	n, err := w.Write(rdata)
	if err != nil {
		slog.Error(fmt.Sprintf("There was an error writing the HTTP response bytes: %s", err))
		return
	}
	slog.Debug(fmt.Sprintf("Wrote %d bytes to HTTP response", n))
}

// checkJWT ensures that the incoming message has an Authorization header with a Bearer token.
// It then tries to decrypt the incoming JWT with the HTTP interface's key used only with authenticated agents.
// If that fails, it will try to decrypt the incoming JWT with the HTTP interface's PSK used only with unauthenticated agents.
// After the JWT is decrypted, its claims are validated.
func (h *Handler) checkJWT(request *http.Request) (agentID uuid.UUID, code int) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "request", fmt.Sprintf("%+v", request))
	defer slog.Log(context.Background(), logging.LevelTrace, "exiting from function", "agentID", agentID, "HTTP Status Code", code)
	messageRepo := memory.NewRepository()
	// Make sure the message has a JWT
	token := request.Header.Get("Authorization")
	if token == "" {
		code = 404
		if core.Verbose {
			msg := "incoming request did not contain an Authorization header"
			slog.Warn(msg)
			messageRepo.Add(message.NewMessage(message.Warn, msg))
		}
		return
	}

	// Make sure the Authorization header contains a bearer token
	if !strings.Contains(token, "Bearer eyJ") {
		code = 404
		if core.Verbose {
			slog.Warn("incoming request did not contain a Bearer token")
		}
		return
	}

	jwt := strings.Split(token, " ")[1]

	// Validate JWT using HTTP interface JWT key; Given to authenticated agents by server
	if core.Verbose {
		slog.Info("Checking to see if authorization JWT was signed by server's interface key...")
	}

	var err error
	agentID, err = ValidateJWT(jwt, h.jwtLeeway, h.jwtKey)
	if err != nil {
		// If agentID was returned, then the message contained a JWT encrypted with the HTTP interface key and the claims were likely invalid
		if agentID != uuid.Nil {
			m := fmt.Sprintf("There was an error validating the JWT for Agent %s using the HTTP interface key. Returning 401 instructing the Agent to generate a self-signed JWT and try again. Error: %s", agentID, err)
			slog.Warn(m)
			messageRepo.Add(message.NewMessage(message.Warn, m))
			code = 401
			return
		} else {
			if core.Verbose {
				slog.Error(err.Error())
				msg := "Authorization JWT not signed with server's interface key, trying again with PSK..."
				slog.Info(msg)
				messageRepo.Add(message.NewMessage(message.Info, msg))
			}
			// Validate JWT using interface PSK; Used by unauthenticated agents
			hashedKey := sha256.Sum256(h.psk)
			key := hashedKey[:]
			agentID, err = ValidateJWT(jwt, h.jwtLeeway, key)
			if err != nil {
				var m string
				if agentID == uuid.Nil {
					m = "Orphaned Agent JWT detected. Returning 401 instructing the Agent to generate a self-signed JWT and try again."
				} else {
					m = fmt.Sprintf("There was an error validating the JWT for Agent %s using the listener's PSK. Returning 401 instructing the Agent to generate a self-signed JWT and try again.\n\tError: %s", agentID, err)
				}
				slog.Warn(m)
				messageRepo.Add(message.NewMessage(message.Warn, m))
				code = 401
				return
			}
			if agentID != uuid.Nil {
				if core.Debug {
					msg := fmt.Sprintf("UnAuthenticated JWT from %s", agentID)
					slog.Debug(msg)
					messageRepo.Add(message.NewMessage(message.Debug, msg))
				}
			}
		}
	}
	return
}
