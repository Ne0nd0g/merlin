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

package http2

// This package is used for specific HTTP/2 features that are NOT available in the net/http package

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	// X Packages
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/handlers"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// Server is a structure for the HTTP/2 clear-text (h2c) server
type Server struct {
	servers.Server
	urls []string
	ctx  *handlers.HTTPContext
}

// Template is a structure used to collect the information needed to create an instance with the New() function
type Template struct {
	servers.Template
	X509Key  string // The x.509 private key used for TLS encryption
	X509Cert string // The x.509 public key used for TLS encryption
	PSK      string // The pre-shared key password used prior to Password Authenticated Key Exchange (PAKE)
}

// init registers this server type with the servers package
func init() {
	servers.RegisteredServers["h2c"] = ""
}

// GetOptions returns a map of configurable server options typically used when creating a listener
func GetOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	options["Port"] = "80"
	options["PSK"] = "merlin"
	options["URLS"] = "/"
	return options
}

// New creates a new HTTP2 server object and returns a pointer
// All arguments are taken in as strings and are converted/validate
func New(options map[string]string) (*Server, error) {
	var s Server
	var err error

	// Verify protocol match
	if strings.ToLower(options["Protocol"]) != "h2c" {
		return &s, fmt.Errorf("server protocol mismatch, expected: H2C got: %s", options["Protocol"])
	}
	s.Protocol = servers.H2C

	// Convert port to integer from string
	s.Port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return &s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	mux := http.NewServeMux()

	// Parse URLs
	if options["URLS"] == "" {
		s.urls = []string{"/"}
	} else {
		s.urls = strings.Split(options["URLS"], ",")
	}

	// Add agent handler for each URL
	if options["PSK"] == "" {
		return &s, fmt.Errorf("a Pre-Shared Key (PSK) password must be provided")
	}
	jwtKey := []byte(core.RandStringBytesMaskImprSrc(32)) // Used to sign and encrypt JWT
	opaqueKey := gopaque.CryptoDefault.NewKey(nil)
	s.ctx = &handlers.HTTPContext{PSK: options["PSK"], JWTKey: jwtKey, OpaqueKey: opaqueKey}

	// Add handler with context
	for _, url := range s.urls {
		mux.HandleFunc(url, s.ctx.AgentHTTP)
	}

	h2s := &http2.Server{}
	s.Transport = &http.Server{
		Addr:           options["Interface"] + ":" + options["Port"],
		Handler:        h2c.NewHandler(mux, h2s),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.Interface = options["Interface"]
	s.ID = uuid.NewV4()
	s.State = servers.Stopped

	return &s, nil
}

// Renew generates a new Server object and retains original encryption keys
func Renew(ctx handlers.ContextInterface, options map[string]string) (*Server, error) {
	tempServer, err := New(options)
	if err != nil {
		return tempServer, err
	}

	// Retain server's original JWT key used to sign and encrypt authorization JWT
	tempServer.ctx.JWTKey = ctx.(handlers.HTTPContext).JWTKey

	// Retain server's original OPAQUE key used with OPAQUE registration/authorization
	tempServer.ctx.OpaqueKey = ctx.(handlers.HTTPContext).OpaqueKey

	return tempServer, nil
}

// GetConfiguredOptions returns the server's current configuration for options that can be set by the user
func (s *Server) GetConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = s.Interface
	options["Port"] = fmt.Sprintf("%d", s.Port)
	options["Protocol"] = servers.GetProtocol(s.Protocol)
	options["PSK"] = s.ctx.PSK
	options["URLS"] = strings.Join(s.urls, " ")

	return options
}

// GetContext returns the Server's current context information such as encryption keys
func (s *Server) GetContext() handlers.ContextInterface {
	return *s.ctx
}

// GetInterface function returns the interface that the server is bound to
func (s *Server) GetInterface() string {
	return s.Interface
}

// GetPort function returns the port that the server is bound to
func (s *Server) GetPort() int {
	return s.Port
}

// GetProtocol returns the server's protocol as an integer for a constant in the servers package
func (s *Server) GetProtocol() int {
	return s.Protocol
}

// GetProtocolString function returns the server's protocol
func (s *Server) GetProtocolString() string {
	switch s.Protocol {
	case servers.H2C:
		return "H2C"
	default:
		return "UNKNOWN"
	}
}

// SetOption sets an option for an instantiated server object
func (s *Server) SetOption(option string, value string) error {
	var err error
	// Check non-string options first
	switch strings.ToLower(option) {
	case "interface":
		s.Interface = value
	case "port":
		s.Port, err = strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
		}
	case "protocol":
		return fmt.Errorf("the protocol can not be changed; create a new listener instead")
	case "psk":
		s.ctx.PSK = value
	case "urls":
		s.urls = strings.Split(value, ",")
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// Start the HTTP2 server
func (s *Server) Start() error {
	var g errgroup.Group

	// Catch Panic
	defer func() {
		if r := recover(); r != nil {
			m := fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", servers.GetProtocol(s.GetProtocol()), s.Interface, s.Port, r.(error))
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.Warn,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   true,
			})
		}
	}()

	g.Go(func() error {
		s.State = servers.Running
		return s.Transport.(*http.Server).ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			s.State = servers.Error
			return fmt.Errorf("there was an error with the %s server on %s:%d %s", s.GetProtocolString(), s.Interface, s.Port, err.Error())
		}
	}
	return nil
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() int {
	return s.State
}

// Stop the HTTP2 server
func (s *Server) Stop() error {
	// Shutdown gracefully shuts down the server without interrupting any active connections.
	// This will keep the agent checking in since it is an active connection
	//err = s.Transport.(*http.Server).Shutdown(context.Background())
	// Close immediately closes all active net.Listeners and any connections in state StateNew, StateActive, or StateIdle.
	err := s.Transport.(*http.Server).Close()
	if err != nil {
		return fmt.Errorf("there was an error stopping the HTTP server:\r\n%s", err.Error())
	}
	s.State = servers.Closed
	return nil
}
