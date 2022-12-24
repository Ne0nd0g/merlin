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
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// X Packages
	"golang.org/x/sync/errgroup"

	// 3rd Party
	"github.com/lucas-clemente/quic-go/http3"
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// init registers the server types with the root servers package for discovery
func init() {
	// Register Server
	servers.RegisteredServers[servers.HTTP] = ""
	servers.RegisteredServers[servers.HTTPS] = ""
	servers.RegisteredServers[servers.H2C] = ""
	servers.RegisteredServers[servers.HTTP2] = ""
	servers.RegisteredServers[servers.HTTP3] = ""
}

// Server states
const (
	// Stopped is the server's state when it has not ever been started
	Stopped int = 0
	// Running means the server is actively accepting connections and serving content
	Running int = 1
	// Error is used when there was an error operating the server
	Error int = 2
	// Closed is used when the server was running but has been stopped; it can't be reused again
	Closed int = 3
)

// Server is a structure for an HTTP server that impelents the Server interface
type Server struct {
	id        uuid.UUID // Unique identifier for the Server object
	iface     string    // The network adapter interface the server will listen on
	handler   *handler
	port      int // The port the server will listen on
	protocol  int // The protocol (i.e. HTTP/2 or HTTP/3) the server will use from the servers package
	state     int
	transport interface{} // The server, or transport, that will be used to send and receive traffic
	x509Cert  string
	x509Key   string
	urls      []string
}

// TODO make this template a generic structure across all HTTP servers in the root

// Template is a structure used to collect the information needed to create an instance with the New() function
type Template struct {
	Interface string
	Port      string
	Protocol  string
	X509Key   string // The x.509 private key used for TLS encryption
	X509Cert  string // The x.509 public key used for TLS encryption
	URLS      string // A comma separated list of URL that handle incoming web traffic
	PSK       string // The pre-shared key password used prior to Password Authenticated Key Exchange (PAKE)
	JWTKey    string // 32-byte Base64 encoded key used to sign/encrypt JWTs
}

// TODO update New to take the template instead of an options map

// New creates a new HTTP server based on the passed in Template
func New(options map[string]string) (Server, error) {
	// Verify the options map has a protocol key
	proto, ok := options["Protocol"]
	if !ok {
		return Server{}, fmt.Errorf("http: a protocol key was not provided")
	}
	switch strings.ToLower(proto) {
	case "http", "https", "http2":
		return newHTTP1(options)
	case "h2c":
		return newHTTP2(options)
	case "http3":
		return newHTTP3(options)
	default:
		return Server{}, fmt.Errorf("http: invalid http protocol type: %s", proto)
	}
}

// ConfiguredOptions returns the server's current configuration for options that can be set by the user
func (s *Server) ConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Protocol"] = s.ProtocolString()
	options["Interface"] = s.iface
	options["Port"] = fmt.Sprintf("%d", s.port)
	options["URLS"] = strings.Join(s.urls, ",")
	options["JWTKey"] = base64.StdEncoding.EncodeToString(s.handler.jwtKey)

	if s.protocol != servers.HTTP {
		options["X509Cert"] = s.x509Cert
		options["X509Key"] = s.x509Key
	}
	return options
}

// Handler returns the Server's current context information such as encryption keys
func (s *Server) Handler() *handler {
	return s.handler
}

// Interface function returns the interface that the server is bound to
func (s *Server) Interface() string {
	return s.iface
}

// Port function returns the port that the server is bound to
func (s *Server) Port() int {
	return s.port
}

// Protocol returns the server's protocol as an integer for a constant in the servers package
func (s *Server) Protocol() int {
	return s.protocol
}

// ProtocolString function returns the server's protocol
func (s *Server) ProtocolString() string {
	switch s.protocol {
	case servers.HTTP:
		return "HTTP"
	case servers.HTTPS:
		return "HTTPS"
	case servers.HTTP2:
		return "HTTP2"
	case servers.H2C:
		return "H2C"
	case servers.HTTP3:
		return "HTTP3"
	default:
		return "UNKNOWN"
	}
}

func (s *Server) ID() uuid.UUID {
	return s.id
}

func (s *Server) Restart(options map[string]string) error {
	// TODO Implement this
	return nil
}

// SetOption function sets an option for an instantiated server object
func (s *Server) SetOption(option string, value string) error {
	var err error
	// Check non-string options first
	switch strings.ToLower(option) {
	case "interface":
		s.iface = value
	case "port":
		s.port, err = strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
		}
	case "protocol":
		return fmt.Errorf("the protocol can not be changed; create a new listener instead")
	case "psk":
		s.handler.psk = []byte(value)
	case "urls":
		s.urls = strings.Split(value, ",")
	case "x509cert":
		if s.protocol == servers.HTTPS || s.protocol == servers.HTTP2 {
			s.x509Cert = option
		}
	case "x509key":
		if s.protocol == servers.HTTPS || s.protocol == servers.HTTP2 {
			s.x509Key = option
		}
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// Start function starts the HTTP server and listens for incoming connections
// This function does not return unless there is an error and should be called as Go routine
func (s *Server) Start() {
	var g errgroup.Group

	// Catch Panic
	defer func() {
		if r := recover(); r != nil {
			m := fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", s.Protocol(), s.iface, s.port, r.(error))
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.Warn,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   true,
			})
		}
	}()

	g.Go(func() error {
		s.state = Running
		switch s.protocol {
		case servers.HTTP, servers.H2C:
			return s.transport.(*http.Server).ListenAndServe()
		case servers.HTTPS, servers.HTTP2:
			return s.transport.(*http.Server).ListenAndServeTLS(s.x509Cert, s.x509Key)
		case servers.HTTP3:
			if s.x509Key != "" && s.x509Cert != "" {
				return s.transport.(*http3.Server).ListenAndServeTLS(s.x509Cert, s.x509Key)
			}
			return s.transport.(*http3.Server).ListenAndServe()
		default:
			return fmt.Errorf("could not start HTTP server, invalid protocol %d, %s", s.protocol, State(s.protocol))
		}
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			s.state = Error
			messages.SendBroadcastMessage(messages.ErrorMessage(fmt.Sprintf("there was an error with the %s server on %s:%d %s", s.ProtocolString(), s.iface, s.port, err.Error())))
		}
	}
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() string {
	return State(s.state)
}

// Stop function stops the server
func (s *Server) Stop() (err error) {
	switch s.protocol {
	case servers.HTTP3:
		// The http3 Close() sends a QUIC CONNECTION_CLOSE frame
		err = s.transport.(*http3.Server).Close()
		// As of quic-go v0.17.3 CloseGracefully is not implemented which means no CONNECTION_CLOSE or GOAWAY frames are sent
		// CloseGracefully() will not release the port since it is not implemented
	default:
		// Don't use Shutdown because it won't immediately release the port and will allow traffic to continue
		err = s.transport.(*http.Server).Close()
	}

	if err != nil {
		return fmt.Errorf("there was an error stopping the HTTP server:\r\n%s", err.Error())
	}
	s.state = Closed
	return
}

// State is used to transform a server state constant into a string for use in written messages or logs
func State(state int) string {
	switch state {
	case Stopped:
		return "Stopped"
	case Running:
		return "Running"
	case Error:
		return "Error"
	case Closed:
		return "Closed"
	default:
		return "Undefined"
	}
}

// GetDefaultOptions returns a map of configurable server options typically used when creating a listener
func GetDefaultOptions(protocol int) map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	if protocol == servers.HTTP {
		options["Port"] = "80"
	} else {
		options["Port"] = "443"
	}

	options["URLS"] = "/"

	if protocol != servers.HTTP && protocol != servers.H2C {
		options["X509Cert"] = filepath.Join(string(core.CurrentDir), "data", "x509", "server.crt")
		options["X509Key"] = filepath.Join(string(core.CurrentDir), "data", "x509", "server.key")
	}

	switch protocol {
	case servers.HTTP:
		options["Protocol"] = "HTTP"
	case servers.HTTPS:
		options["Protocol"] = "HTTPS"
	case servers.HTTP2:
		options["Protocol"] = "HTTP2"
	case servers.H2C:
		options["Protocol"] = "H2C"
	case servers.HTTP3:
		options["Protocol"] = "HTTP3"
	default:
		options["Protocol"] = "HTTP-UNKNOWN"
	}

	return options
}

// Renew generates a new Server object and retains original encryption keys
func Renew(ctx handler, options map[string]string) (Server, error) {
	tempServer, err := New(options)
	if err != nil {
		return tempServer, err
	}

	// Retain server's original JWT key used to sign and encrypt authorization JWT
	tempServer.handler.jwtKey = ctx.jwtKey

	return tempServer, nil
}
