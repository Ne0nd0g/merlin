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

package http3

import (
	// Standard
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// X Packages
	"golang.org/x/sync/errgroup"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/handlers"
	"github.com/Ne0nd0g/merlin/pkg/servers"
	"github.com/Ne0nd0g/merlin/pkg/util"
)

// Server is a structure for the HTTP3 server
type Server struct {
	servers.Server
	x509Cert string
	x509Key  string
	urls     []string
	ctx      *handlers.HTTPContext
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
	servers.RegisteredServers["http3"] = ""
}

// GetOptions returns a map of configurable server options typically used when creating a listener
func GetOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	options["Port"] = "443"
	options["PSK"] = "merlin"
	options["URLS"] = "/"
	options["X509Cert"] = filepath.Join(core.CurrentDir, "data", "x509", "server.crt")
	options["X509Key"] = filepath.Join(core.CurrentDir, "data", "x509", "server.key")
	return options
}

// New creates a new HTTP3 server object and returns a pointer
// All arguments are taken in as strings and are converted/validate
func New(options map[string]string) (*Server, error) {
	var s Server
	var certificates *tls.Certificate
	var err error

	// Verify protocol match
	if strings.ToLower(options["Protocol"]) != "http3" {
		return &s, fmt.Errorf("server protocol mismatch, expected: HTTP3 got: %s", options["Protocol"])
	}
	s.Protocol = servers.HTTP3

	// Convert port to integer from string
	s.Port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return &s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	// Verify X509 Key file exists and can be parsed
	certificates, err = util.GetTLSCertificates(options["X509Cert"], options["X509Key"])
	if err != nil {
		m := fmt.Sprintf("Certificate was not found at: %s\r\n", options["X509Cert"])
		m += "Creating in-memory x.509 certificate used for this session only"
		messages.SendBroadcastMessage(messages.UserMessage{
			Level:   messages.Note,
			Message: m,
			Time:    time.Now().UTC(),
			Error:   false,
		})
		certificates, err = util.GenerateTLSCert(nil, nil, nil, nil, nil, nil, true)
		if err != nil {
			return &s, err
		}
		// Leave empty to force the use of the server's TLSConfig
		s.x509Cert = ""
		s.x509Key = ""
	} else {
		s.x509Cert = options["X509Cert"]
		s.x509Key = options["X509Key"]
	}
	insecure, errI := util.CheckInsecureFingerprint(*certificates)
	if errI != nil {
		return &s, errI
	}

	if insecure {
		m := fmt.Sprintf("Insecure publicly distributed Merlin x.509 testing certificate in use for HTTP/3 server on %s:%s\r\n", options["Interface"], options["Port"])
		m += "Additional details: https://merlin-c2.readthedocs.io/en/latest/server/x509.html"
		messages.SendBroadcastMessage(messages.UserMessage{
			Level:   messages.Warn,
			Message: m,
			Time:    time.Now().UTC(),
			Error:   false,
		})
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

	s.Transport = &http3.Server{
		Addr:           options["Interface"] + ":" + options["Port"],
		Port:           s.Port,
		Handler:        mux,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{*certificates}, MinVersion: tls.VersionTLS12},
		QuicConfig: &quic.Config{
			// Opted for a long timeout to prevent the client from sending a HTTP/2 PING Frame
			MaxIdleTimeout:  time.Until(time.Now().AddDate(0, 42, 0)),
			KeepAlivePeriod: time.Second * 0,
		},
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
	options["X509Cert"] = s.x509Cert
	options["X509Key"] = s.x509Key

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
	case servers.HTTP3:
		return "HTTP3"
	default:
		return "UNKNOWN"
	}
}

// SetOption function sets an option for an instantiated server object
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
	case "x509cert":
		s.x509Cert = option
	case "x509key":
		s.x509Key = option
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// Start function starts the HTTP3 server
func (s *Server) Start() error {
	var g errgroup.Group

	// Catch Panic
	defer func() {
		if r := recover(); r != nil {
			m := fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", servers.GetProtocol(s.Protocol), s.Interface, s.Port, r.(error))
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
		if s.x509Key != "" && s.x509Cert != "" {
			return s.Transport.(*http3.Server).ListenAndServeTLS(s.x509Cert, s.x509Key)
		}
		return s.Transport.(*http3.Server).ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "server closed") {
			s.State = servers.Error
			return fmt.Errorf("there was an error starting the %s server on %s:%d %s", servers.GetProtocol(s.Protocol), s.Interface, s.Port, err.Error())
		}
	}
	return nil
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() int {
	return s.State
}

// Stop function stops the HTTP3 server
func (s *Server) Stop() error {
	// The http3 Close() sends a QUIC CONNECTION_CLOSE frame
	err := s.Transport.(*http3.Server).Close()
	// As of quic-go v0.17.3 CloseGracefully is not implemented which means no CONNECTION_CLOSE or GOAWAY frames are sent
	// CloseGracefully() will not release the port since it is not implemented
	//err := s.Transport.(*http3.Server).CloseGracefully(time.Second * 0)
	if err != nil {
		return fmt.Errorf("there was an error stopping the HTTP3 server:\r\n%s", err.Error())
	}
	s.State = servers.Closed

	return nil
}
