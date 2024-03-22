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
	// Standard
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// X Packages
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message"
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	"github.com/Ne0nd0g/merlin/v2/pkg/servers"
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

// Server is a structure for an HTTP server that implements the Server interface
type Server struct {
	id        uuid.UUID // Unique identifier for the Server object
	iface     string    // The network adapter interface the server will listen on
	handler   *Handler
	port      int // The port the server will listen on
	protocol  int // The protocol (i.e., HTTP/2 or HTTP/3) the server will use from the servers' package
	state     int
	transport interface{} // The server, or transport, that will be used to send and receive traffic
	listener  net.Listener
	udpConn   *net.UDPConn
	x509Cert  string
	x509Key   string
	urls      []string
	psk       string
	jwtKey    string        // A Base64 encoded 32-byte key used to sign JSON Web Tokens
	jwtLeeway time.Duration // The amount of flexibility allowed in the JWT expiration time. Less than 0 disables checking JWT expiration
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
	JWTLeeway string // The amount of flexibility allowed in the JWT expiration time. Less than 0 disables checking JWT expiration
}

// TODO update New to take the template instead of an options map

// New creates a new HTTP server based on the passed in Template
func New(options map[string]string) (Server, error) {
	var err error
	var s Server
	s.state = Stopped

	id, ok := options["ID"]
	if ok {
		s.id, err = uuid.Parse(id)
		if err != nil {
			return s, fmt.Errorf("the \"ID\" key UUID value (%s) was incorrect, please provide a correct one", id)
		}
	} else {
		s.id = uuid.New()
	}

	// Protocol
	proto, ok := options["Protocol"]
	if ok {
		proto = strings.ToLower(proto)
	} else {
		return s, fmt.Errorf("the \"Protocol\" key was not found in the options map and is required")
	}
	switch proto {
	case "http":
		s.protocol = servers.HTTP
	case "https":
		s.protocol = servers.HTTPS
	case "http2":
		s.protocol = servers.HTTP2
	case "h2c":
		s.protocol = servers.H2C
	case "http3":
		s.protocol = servers.HTTP3
	default:
		return Server{}, fmt.Errorf("http: invalid http protocol type: %s", proto)
	}

	// Interface
	s.iface, ok = options["Interface"]
	if !ok {
		return s, fmt.Errorf("the \"Interface\" key was not found in the options map and is required")
	}

	// Port
	port, ok := options["Port"]
	if !ok {
		return s, fmt.Errorf("the \"Port\" key was not found in the options map and is required")
	}
	// Convert port to integer from string
	s.port, err = strconv.Atoi(port)
	if err != nil {
		return s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	// X.509 Certificate
	if cert, ok := options["X509Cert"]; ok {
		s.x509Cert = cert
	}

	// X.509 Key
	if key, ok := options["X509Key"]; ok {
		s.x509Key = key
	}

	// Parse URLs
	urls, _ := options["URLS"]
	if urls == "" {
		s.urls = []string{"/"}
	} else {
		s.urls = strings.Split(urls, ",")
	}

	// Pre-Shared Key
	s.psk, ok = options["PSK"]
	if !ok {
		return s, fmt.Errorf("the \"PSK\" key was not found in the options map and is required")
	}

	// JWT Key
	jwtKey, ok := options["JWTKey"]
	if !ok {
		return s, fmt.Errorf("the \"JWTKey\" key was not found in the options map and is required")
	}

	// Key must be 32 bytes
	jwt, err := base64.StdEncoding.DecodeString(options["JWTKey"])
	if err != nil {
		return s, fmt.Errorf("there was an error base64 decoding the provided JWT Key %s: %s", options["JWTKey"], err)
	}
	if len(jwt) != 32 {
		return s, fmt.Errorf("the provided JWT key was %d bytes but must be 32 bytes", len(jwt))
	}
	s.jwtKey = jwtKey

	// JWT Leeway
	leeway, ok := options["JWTLeeway"]
	if !ok {
		return s, fmt.Errorf("the \"JWTLeeway\" key was not found in the options map and is required")
	}
	s.jwtLeeway, err = time.ParseDuration(leeway)
	if err != nil {
		return s, fmt.Errorf("there was an error parsing the JWTLeeway duration %s: %s", leeway, err)
	}
	return s, nil
}

// Addr returns the network interface and port it is bound to
func (s *Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.iface, s.port)
}

// ConfiguredOptions returns the server's current configuration for options that can be set by the user
func (s *Server) ConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Protocol"] = s.ProtocolString()
	options["Interface"] = s.iface
	options["Port"] = fmt.Sprintf("%d", s.port)
	options["URLS"] = strings.Join(s.urls, ",")
	options["JWTKey"] = s.jwtKey
	options["JWTLeeway"] = s.jwtLeeway.String()

	if s.protocol != servers.HTTP && s.protocol != servers.H2C {
		options["X509Cert"] = s.x509Cert
		options["X509Key"] = s.x509Key
	}
	return options
}

// Handler returns the Server's current context information such as encryption keys
func (s *Server) Handler() *Handler {
	return s.handler
}

// Interface function returns the interface that the server is bound to
func (s *Server) Interface() string {
	return s.iface
}

// Listen creates a TCP network listener on the server's network interface and port
func (s *Server) Listen() (err error) {
	err = s.generateServer()
	if err != nil {
		err = fmt.Errorf("there was an error generating a new %s server: %s", s, err)
		slog.Error(err.Error())
		return
	}

	if s.protocol != servers.HTTP3 {
		s.listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", s.iface, s.port))
		if err != nil {
			err = fmt.Errorf("there was an error creating a listener for the %s server: %s", s, err)
			slog.Error(err.Error())
			return
		}
	} else {
		s.udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.ParseIP(s.iface),
			Port: s.port,
			Zone: "",
		})
		if err != nil {
			err = fmt.Errorf("there was an error creating a listener for the %s server: %s", s, err)
			slog.Error(err.Error())
			return
		}
	}

	return
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
			slog.Error(fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", s.ProtocolString(), s.iface, s.port, r.(error)))
		}
	}()

	g.Go(func() error {
		s.state = Running
		switch s.protocol {
		case servers.HTTP, servers.H2C:
			return s.transport.(*http.Server).Serve(s.listener)
		case servers.HTTPS, servers.HTTP2:
			return s.transport.(*http.Server).ServeTLS(s.listener, s.x509Cert, s.x509Key)
		case servers.HTTP3:
			//if s.x509Key != "" && s.x509Cert != "" {
			//	return s.transport.(*http3.Server).ListenAndServeTLS(s.x509Cert, s.x509Key)
			//}
			return s.transport.(*http3.Server).Serve(s.udpConn)
		default:
			return fmt.Errorf("could not start HTTP server, invalid protocol %d, %s", s.protocol, State(s.protocol))
		}
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed && err != quic.ErrServerClosed {
			s.state = Error
			slog.Error(fmt.Sprintf("there was an error with the %s server on %s:%d %s", s.ProtocolString(), s.iface, s.port, err.Error()))
		}
	}
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() string {
	return State(s.state)
}

// Stop function stops the server
func (s *Server) Stop() (err error) {
	// If the server isn't running, return
	if s.state != Running {
		return nil
	}

	if s.transport == nil {
		return fmt.Errorf("the %s server on %s:%d was never started", s.ProtocolString(), s.iface, s.port)
	}

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

// String function returns the server's protocol as a string
// (e.g., HTTP, HTTPS, HTTP2, H2C, HTTP3)
func (s *Server) String() string {
	return s.ProtocolString()
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
	if protocol == servers.HTTP || protocol == servers.H2C {
		options["Port"] = "80"
	} else {
		options["Port"] = "443"
	}
	options["JWTKey"] = base64.StdEncoding.EncodeToString([]byte(core.RandStringBytesMaskImprSrc(32)))
	options["JWTLeeway"] = "1m"
	options["URLS"] = "/"

	if protocol != servers.HTTP && protocol != servers.H2C {
		current, err := os.Getwd()
		if err != nil {
			slog.Error(fmt.Sprintf("there was an error getting the current working directory: %s", err))
		}
		options["X509Cert"] = filepath.Join(current, "data", "x509", "server.crt")
		options["X509Key"] = filepath.Join(current, "data", "x509", "server.key")
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

// generateServer creates a new http.Server structure based on the configuration and assigns it to this package's Server structure
func (s *Server) generateServer() error {
	// JWT
	jwt, err := base64.StdEncoding.DecodeString(s.jwtKey)
	if err != nil {
		return fmt.Errorf("there was an error base64 decoding the provided JWT Key %s: %s", s.jwtKey, err)
	}

	// Handler
	s.handler = &Handler{
		// Used to sign and encrypt JWT
		listener:  s.id,
		jwtKey:    jwt,
		jwtLeeway: s.jwtLeeway,
		psk:       []byte(s.psk),
	}

	// Add multiplexer handler for URLs
	mux := http.NewServeMux()
	for _, url := range s.urls {
		mux.HandleFunc(url, s.handler.agentHandler)
	}

	// Add server
	switch s.protocol {
	case servers.HTTP, servers.HTTPS, servers.HTTP2:
		s.transport = &http.Server{
			Addr:              fmt.Sprintf("%s:%d", s.iface, s.port),
			Handler:           mux,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			ReadHeaderTimeout: 30 * time.Second,
			MaxHeaderBytes:    1 << 20,
			ErrorLog:          log.Default(),
		}
	case servers.H2C:
		h2s := &http2.Server{}
		s.transport = &http.Server{
			Addr:              fmt.Sprintf("%s:%d", s.iface, s.port),
			Handler:           h2c.NewHandler(mux, h2s),
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: 30 * time.Second,
			MaxHeaderBytes:    1 << 20,
			ErrorLog:          log.Default(),
		}
	case servers.HTTP3:

		s.transport = &http3.Server{
			Addr:           fmt.Sprintf("%s:%d", s.iface, s.port),
			Port:           s.port,
			Handler:        mux,
			MaxHeaderBytes: 1 << 20,
			//TLSConfig:      &tls.Config{Certificates: []tls.Certificate{*certificates}, MinVersion: tls.VersionTLS12},
			QuicConfig: &quic.Config{
				// Opted for a long timeout to prevent the client from sending an HTTP/2 PING Frame
				MaxIdleTimeout:  time.Until(time.Now().AddDate(0, 42, 0)),
				KeepAlivePeriod: time.Second * 0,
			},
		}
	default:
		return fmt.Errorf("pkg/servers/http.generateServer(): unhandled server type %d", s.protocol)
	}

	// Add TLS X509 certificates
	if s.protocol == servers.HTTPS || s.protocol == servers.HTTP2 || s.protocol == servers.HTTP3 {
		certificates, err := GetTLSCertificates(s.x509Cert, s.x509Key)
		if err != nil {
			m := fmt.Sprintf("Certificate was not found at: \"%s\"\n", s.x509Cert)
			m += "Creating in-memory x.509 certificate used for this session only"
			slog.Info(fmt.Sprintf("Certificate was not found at: %s. Creating in-memory x.509 certificate used for this session only", s.x509Cert))
			memory.NewRepository().Add(message.NewMessage(message.Note, m))
			// Set to blank to force the HTTP server to use its TLS config. ListenAndServeTLS will fail with invalid file paths
			s.x509Key = ""
			s.x509Cert = ""
			// Generate in-memory certificates
			certificates, err = GenerateTLSCert(nil, nil, nil, nil, nil, nil, true)
			if err != nil {
				return err
			}
		}

		insecure, err := CheckInsecureFingerprint(*certificates)
		if err != nil {
			return err
		}

		if insecure {
			m := fmt.Sprintf("Insecure publicly distributed Merlin x.509 testing certificate in use for %s server on %s:%d\n", s.ProtocolString(), s.iface, s.port)
			m += "Additional details: https://merlin-c2.readthedocs.io/en/latest/server/x509.html"
			slog.Info(m)
			memory.NewRepository().Add(message.NewMessage(message.Note, m))
		}
		switch s.protocol {
		case servers.HTTPS, servers.HTTP2:
			tlsConfig := tls.Config{Certificates: []tls.Certificate{*certificates}} // #nosec G402 TLS version is not configured to facilitate dynamic JA3 configurations
			s.transport.(*http.Server).TLSConfig = &tlsConfig
		case servers.HTTP3:
			tlsConfig := tls.Config{Certificates: []tls.Certificate{*certificates}} // #nosec G402 TLS version is not configured to facilitate dynamic JA3 configurations
			s.transport.(*http3.Server).TLSConfig = http3.ConfigureTLSConfig(&tlsConfig)
		}
	}
	return nil
}
