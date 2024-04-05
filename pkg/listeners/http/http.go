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

// Package http contains structures and repositories to create, store, and manage HTTP based Agent listeners
package http

import (
	// Standard
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/authenticators"
	"github.com/Ne0nd0g/merlin/v2/pkg/authenticators/none"
	"github.com/Ne0nd0g/merlin/v2/pkg/authenticators/opaque"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"github.com/Ne0nd0g/merlin/v2/pkg/servers"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer"
	b64 "github.com/Ne0nd0g/merlin/v2/pkg/transformer/encoders/base64"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encoders/gob"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encoders/hex"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encrypters/aes"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encrypters/jwe"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encrypters/rc4"
	"github.com/Ne0nd0g/merlin/v2/pkg/transformer/encrypters/xor"
)

// Listener is an aggregate structure that implements the Listener interface used to listen for and handle Agent message traffic
type Listener struct {
	server       servers.ServerInterface      // server is the root entity and interface to interact with server objects
	auth         authenticators.Authenticator // auth is the process or method to authenticate Agents
	transformers []transformer.Transformer    // transformers is a list of transformers to encode and encrypt Agent messages
	description  string                       // description of the listener
	name         string                       // name of the listener
	options      map[string]string            // options is a map of the listener's configurable options used with NewHTTPListener function
	psk          []byte                       // psk is the Listener's Pre-Shared Key used for initial message encryption until the Agent is authenticated
	jwt          []byte                       // jwt is the Listener's key to sign and encrypt JSON Web Tokens used for HTTP communications
	agentService *agent.Service               // agentService is used to interact with Agents
}

// NewHTTPListener is a factory that creates and returns a Listener aggregate that implements the Listener interface
// The HTTP listener requires an instantiated server object to send/receive messages with Agents
func NewHTTPListener(server servers.ServerInterface, options map[string]string) (listener Listener, err error) {
	// Ensure a listener name was provided
	listener.name = options["Name"]
	if listener.name == "" {
		return listener, fmt.Errorf("a listener name must be provided")
	}

	// Get a new server object for the listener
	//listener.id = uuid.New()
	listener.server = server
	listener.description = options["Description"]

	// Set the PSK
	if _, ok := options["PSK"]; ok {
		psk := sha256.Sum256([]byte(options["PSK"]))
		listener.psk = psk[:]
	}

	// Set the JWT Key
	if _, ok := options["JWTKey"]; ok {
		listener.jwt, err = base64.StdEncoding.DecodeString(options["JWTKey"])
		if err != nil {
			return
		}
	}

	if _, ok := options["Transforms"]; ok {
		transforms := strings.Split(options["Transforms"], ",")
		for _, transform := range transforms {
			var t transformer.Transformer
			switch strings.ToLower(transform) {
			case "aes":
				t = aes.NewEncrypter()
			case "base64-byte":
				t = b64.NewEncoder(b64.BYTE)
			case "base64-string":
				t = b64.NewEncoder(b64.STRING)
			case "hex-byte":
				t = hex.NewEncoder(hex.BYTE)
			case "hex-string":
				t = hex.NewEncoder(hex.STRING)
			case "gob-base":
				t = gob.NewEncoder(gob.BASE)
			case "gob-string":
				t = gob.NewEncoder(gob.STRING)
			case "jwe":
				t = jwe.NewEncrypter()
			case "rc4":
				t = rc4.NewEncrypter()
			case "xor":
				t = xor.NewEncrypter()
			default:
				err = fmt.Errorf("pkg/listeners/http.New(): unhandled transform type: %s", transform)
			}
			if err != nil {
				return
			}
			listener.transformers = append(listener.transformers, t)
		}
	}

	// Add the (optional) authenticator
	if _, ok := options["Authenticator"]; ok {
		switch strings.ToLower(options["Authenticator"]) {
		case "opaque":
			listener.auth, err = opaque.NewAuthenticator()
			if err != nil {
				return listener, fmt.Errorf("pkg/listeners/tcp.NewHTTPListener(): there was an error getting the authenticator: %s", err)
			}
		default:
			listener.auth = none.NewAuthenticator()
		}
	}

	// Add the agent service
	listener.agentService = agent.NewAgentService()

	// Store the passed in options map
	listener.options = options

	return listener, nil
}

// DefaultOptions returns a map of configurable listener options that will subsequently be passed to the NewHTTPListener function
func DefaultOptions() map[string]string {
	options := make(map[string]string)
	options["Name"] = "My HTTP Listener"
	options["Authenticator"] = "OPAQUE"
	options["Description"] = "Default HTTP Listener"
	options["PSK"] = "merlin"
	options["Transforms"] = "jwe,gob-base"
	return options
}

// Addr returns the network interface and port the peer-to-peer Agent is using
func (l *Listener) Addr() string {
	return l.server.Addr()
}

// Authenticate takes data coming into the listener from an agent and passes it to the listener's configured
// authenticator to authenticate the agent. Once an agent is authenticated, this function will no longer be used.
func (l *Listener) Authenticate(id uuid.UUID, data interface{}) (messages.Base, error) {
	auth := l.auth
	return auth.Authenticate(id, data)
}

// Authenticator returns the authenticator the listener is configured to use
func (l *Listener) Authenticator() authenticators.Authenticator {
	return l.auth
}

// ConfiguredOptions returns the server's current configuration for options that can be set by the user
func (l *Listener) ConfiguredOptions() map[string]string {
	// Server configuration
	options := l.server.ConfiguredOptions()
	// Listener configuration
	options["ID"] = l.server.ID().String()
	options["Name"] = l.name
	options["Description"] = l.description
	options["Authenticator"] = l.auth.String()
	// PSK is stored in l.PSK as a sha256 hash of the passed in clear-text PSK
	options["PSK"] = l.options["PSK"]

	transforms := make([]string, len(l.transformers))
	options["Transforms"] = ""
	for i, transform := range l.transformers {
		transforms[i] = fmt.Sprintf("%s", transform)
	}
	options["Transforms"] = strings.Join(transforms, ",")

	return options
}

// Construct takes in a messages.Base structure that is ready to be sent to an agent and runs all the data transforms
// on it to encode and encrypt it. If an empty key is passed in, then the listener's interface encryption key will be used.
func (l *Listener) Construct(msg messages.Base, key []byte) (data []byte, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "message", fmt.Sprintf("%+v", msg), "key", fmt.Sprintf("%x", key))
	defer slog.Log(context.Background(), logging.LevelTrace, "exiting from function", "data", fmt.Sprintf("%X", data), "error", err)

	//fmt.Printf("pkg/listeners/http.Construct(): entering into function with Base message: %+v and key: %x\n", msg, key)
	// Get a JWT and add it to the message
	// Agent's that haven't authenticated won't be in the repository and will return an error and that is OK
	// A zero will be passed in as the lifetime
	lifetime, _ := l.agentService.Lifetime(msg.ID)

	// Only provide a token if the agent is authenticated
	if l.agentService.Authenticated(msg.ID) {
		msg.Token, err = GetJWT(msg.ID, lifetime, l.jwt)
		if err != nil {
			return nil, fmt.Errorf("pkg/listeners/http.Construct(): there was an error creating a JWT with key %x: %s", l.jwt, err)
		}
	}

	if len(key) == 0 {
		key = l.psk
	}

	for i := len(l.transformers); i > 0; i-- {

		if i == len(l.transformers) {
			// First call should always take a Base message
			data, err = l.transformers[i-1].Construct(msg, key)
		} else {
			data, err = l.transformers[i-1].Construct(data, key)
		}
		if err != nil {
			return nil, fmt.Errorf("pkg/listeners/http.Construct(): there was an error calling the transformer construct function: %s", err)
		}
	}
	return
}

// Deconstruct takes in data that an agent sent to the listener and runs all the listener's transforms on it until
// a messages.Base structure is returned. The key is used for decryption transforms. If an empty key is passed in, then
// the listener's interface encryption key will be used.
func (l *Listener) Deconstruct(data, key []byte) (messages.Base, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "data length", len(data), "key", fmt.Sprintf("%x", key))

	// Get the listener's interface encryption key
	if len(key) == 0 {
		key = l.psk
	}

	for _, transform := range l.transformers {
		slog.Log(context.Background(), logging.LevelTrace, fmt.Sprintf("Transformer %T: %+v\n", transform, transform))
		//fmt.Printf("Transformer %T: %+v\n", transform, transform)
		ret, err := transform.Deconstruct(data, key)
		if err != nil {
			return messages.Base{}, err
		}
		switch ret.(type) {
		case []uint8:
			data = ret.([]byte)
		case string:
			data = []byte(ret.(string)) // Probably not what I should be doing
		case messages.Base:
			//fmt.Printf("pkg/listeners/http.Deconstruct(): returning Base message: %+v\n", ret.(messages.Base))
			slog.Log(context.Background(), logging.LevelTrace, "returning Base message", "message", fmt.Sprintf("%+v", ret.(messages.Base)))
			return ret.(messages.Base), nil
		default:
			return messages.Base{}, fmt.Errorf("pkg/listeners/http.Deconstruct(): unhandled data type for Deconstruct(): %T", ret)
		}
	}
	return messages.Base{}, fmt.Errorf("pkg/listeners/http.Deconstruct(): unable to transform data into messages.Base structure")
}

// Description returns the listener's description
func (l *Listener) Description() string {
	return l.description
}

// ID returns the listener's unique identifier
func (l *Listener) ID() uuid.UUID {
	return l.server.ID()
}

// Name returns the listener's name
func (l *Listener) Name() string {
	return l.name
}

// Options returns the original map of options passed into the NewHTTPListener function
func (l *Listener) Options() map[string]string {
	return l.options
}

// Protocol returns a constant from the listeners package that represents the protocol type of this listener
func (l *Listener) Protocol() int {
	return listeners.HTTP
}

// PSK returns the listener's pre-shared key used for encrypting & decrypting agent messages
func (l *Listener) PSK() string {
	return string(l.psk)
}

// Server returns the listener's embedded server structure
func (l *Listener) Server() *servers.ServerInterface {
	return &l.server
}

// Status returns the status of the embedded server's state (e.g., running or stopped)
func (l *Listener) Status() string {
	return l.server.Status()
}

// String returns the listener's name
func (l *Listener) String() string {
	return l.name
}

// SetOption sets the value for a configurable option on the Listener
func (l *Listener) SetOption(option string, value string) error {
	var err error
	var key string
	switch strings.ToLower(option) {
	case "authenticator":
		switch strings.ToLower(value) {
		case "opaque":
			var err error
			l.auth, err = opaque.NewAuthenticator()
			if err != nil {
				return fmt.Errorf("pkg/listeners/http.SetOptions(): there was an error getting the authenticator: %s", err)
			}
		default:
			l.auth = none.NewAuthenticator()
		}
		key = "Authenticator"
	case "description":
		l.description = value
		key = "Description"
	case "name":
		l.name = value
		key = "Name"
	case "psk":
		psk := sha256.Sum256([]byte(value))
		l.psk = psk[:]
		// PSK needs to be set on the Server too
		err = l.server.SetOption(option, value)
		key = "PSK"
	case "transforms":
		var tl []transformer.Transformer
		transforms := strings.Split(value, ",")
		for _, transform := range transforms {
			var t transformer.Transformer
			switch strings.ToLower(transform) {
			case "aes":
				t = aes.NewEncrypter()
			case "base64-byte":
				t = b64.NewEncoder(b64.BYTE)
			case "base64-string":
				t = b64.NewEncoder(b64.STRING)
			case "hex-byte":
				t = hex.NewEncoder(hex.BYTE)
			case "hex-string":
				t = hex.NewEncoder(hex.STRING)
			case "gob-base":
				t = gob.NewEncoder(gob.BASE)
			case "gob-string":
				t = gob.NewEncoder(gob.STRING)
			case "jwe":
				t = jwe.NewEncrypter()
			case "rc4":
				t = rc4.NewEncrypter()
			case "xor":
				t = xor.NewEncrypter()
			default:
				return fmt.Errorf("pkg/listeners/http.SetOption(): unhandled transform type: %s", transform)
			}
			tl = append(tl, t)
		}
		l.transformers = tl
		key = "Transforms"
	// Protocol, Interface, Port, URLS, JWTKey, X509CERT, X509KEY are handled by the server
	default:
		err = l.server.SetOption(option, value)
		if err != nil {
			return fmt.Errorf("pkg/listeners/http.SetOptions(): %s", err)
		}
		return nil
	}
	_, ok := l.options[key]
	if !ok {
		return fmt.Errorf("pkg/listeners/http.SetOptions(): invalid options map key: \"%s\"", key)
	}
	l.options[key] = value
	return nil
}

// Transformers returns a list of transforms the lister is configured to use
func (l *Listener) Transformers() []transformer.Transformer {
	return l.transformers
}
