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

package http

// HTTP2 is in this package because net/http inherently supports the protocol

import (
	// Standard
	"context"
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
	URLS     string // A comma separated list of URL that handle incoming web traffic
	PSK      string // The pre-shared key password used prior to Password Authenticated Key Exchange (PAKE)
}

// init registers this server type with the servers package
func init() {
	// Register Server
	servers.RegisteredServers["http"] = ""
	servers.RegisteredServers["https"] = ""
	servers.RegisteredServers["http2"] = ""
}

// GetOptions returns a map of configurable server options typically used when creating a listener
func GetOptions(protocol string) map[string]string {
	options := make(map[string]string)
	options["Interface"] = "127.0.0.1"
	options["Port"] = "443"
	//options["Protocol"] = protocol
	options["PSK"] = "merlin"
	options["URLS"] = "/"

	if strings.ToLower(protocol) != "http" {
		options["X509Cert"] = filepath.Join(string(core.CurrentDir), "data", "x509", "server.crt")
		options["X509Key"] = filepath.Join(string(core.CurrentDir), "data", "x509", "server.key")
	}
	return options
}

// New creates a new HTTP server object and returns a pointer
// All arguments are taken in as strings and are converted/validate
func New(options map[string]string) (*Server, error) {
	var s Server
	var certificates *tls.Certificate
	var err error
	proto := strings.ToLower(options["Protocol"])

	// Verify protocol match
	if proto != "http" && proto != "https" && proto != "http2" {
		return &s, fmt.Errorf("server protocol mismatch, expected: http, https, or http2 got: %s", proto)
	}
	switch proto {
	case "http":
		s.Protocol = servers.SERVER_PROTOCOL_HTTP
	case "https":
		s.Protocol = servers.SERVER_PROTOCOL_HTTPS
	case "http2":
		s.Protocol = servers.SERVER_PROTOCOL_HTTP2
	}

	// Convert port to integer from string
	s.Port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return &s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	// Verify X509 Key file exists and can be parsed
	if s.Protocol == servers.SERVER_PROTOCOL_HTTPS || s.Protocol == servers.SERVER_PROTOCOL_HTTP2 {
		certificates, err = util.GetTLSCertificates(options["X509Cert"], options["X509Key"])
		if err != nil {
			m := fmt.Sprintf("Certificate was not found at: %s\r\n", options["X509Cert"])
			m += "Creating in-memory x.509 certificate used for this session only"
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.MESSAGE_NOTE,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   false,
			})
			// Generate in-memory certificates
			certificates, err = util.GenerateTLSCert(nil, nil, nil, nil, nil, nil, true)
			if err != nil {
				return &s, err
			} else {
				// Leave empty to force the use of the server's TLSConfig
				s.x509Cert = ""
				s.x509Key = ""
			}
		} else {
			s.x509Cert = options["X509Cert"]
			s.x509Key = options["X509Key"]
		}
		insecure, errI := util.CheckInsecureFingerprint(*certificates)
		if errI != nil {
			return &s, errI
		}
		if insecure {
			m := fmt.Sprintf("Insecure publicly distributed Merlin x.509 testing certificate in use for %s server on %s:%s\r\n", proto, options["Interface"], options["Port"])
			m += "Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates"
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.MESSAGE_WARN,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   false,
			})
		}
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
	for _, url := range s.urls {
		mux.HandleFunc(url, s.ctx.AgentHTTP)
	}

	s.Transport = &http.Server{
		Addr:           options["Interface"] + ":" + options["Port"],
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Add X.509 certificates if using TLS
	if s.Protocol == servers.SERVER_PROTOCOL_HTTPS || s.Protocol == servers.SERVER_PROTOCOL_HTTP2 {
		s.Transport.(*http.Server).TLSConfig = &tls.Config{Certificates: []tls.Certificate{*certificates}}
	}

	s.Interface = options["Interface"]
	s.ID = uuid.NewV4()
	s.State = servers.SERVER_STATE_STOPPED

	return &s, nil
}

// GetConfiguredOptions returns the server's current configuration for options that can be set by the user
func (s *Server) GetConfiguredOptions() map[string]string {
	options := make(map[string]string)
	options["Interface"] = s.Interface
	options["Port"] = fmt.Sprintf("%d", s.Port)
	options["Protocol"] = s.GetProtocolString()
	options["PSK"] = s.ctx.PSK
	options["URLS"] = strings.Join(s.urls, " ")

	if s.Protocol != servers.SERVER_PROTOCOL_HTTP {
		options["X509Cert"] = s.x509Cert
		options["X509Key"] = s.x509Key
	}
	return options
}

// This function returns the interface that the server is bound to
func (s *Server) GetInterface() string {
	return s.Interface
}

// This function returns the port that the server is bound to
func (s *Server) GetPort() int {
	return s.Port
}

// GetProtocol returns the server's protocol as an integer for a constant in the servers package
func (s *Server) GetProtocol() int {
	return s.Protocol
}

// This function returns the server's protocol
func (s *Server) GetProtocolString() string {
	switch s.Protocol {
	case servers.SERVER_PROTOCOL_HTTP:
		return "HTTP"
	case servers.SERVER_PROTOCOL_HTTPS:
		return "HTTPS"
	case servers.SERVER_PROTOCOL_HTTP2:
		return "HTTP/2"
	default:
		return "UNKNOWN"
	}
}

// This function sets an option for an instantiated server object
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
		s.urls = strings.Split(option, ",")
	case "x509cert":
		if s.Protocol == servers.SERVER_PROTOCOL_HTTPS || s.Protocol == servers.SERVER_PROTOCOL_HTTP2 {
			s.x509Cert = option
		}
	case "x509key":
		if s.Protocol == servers.SERVER_PROTOCOL_HTTPS || s.Protocol == servers.SERVER_PROTOCOL_HTTP2 {
			s.x509Key = option
		}
	default:
		return fmt.Errorf("invalid option: %s", option)
	}
	return nil
}

// This function starts the HTTP server
func (s *Server) Start() error {
	var g errgroup.Group

	// Catch Panic
	defer func() {
		if r := recover(); r != nil {
			m := fmt.Sprintf("The %s server on %s:%d paniced:\r\n%v+\r\n", servers.GetProtocol(s.GetProtocol()), s.Interface, s.Port, r.(error))
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.MESSAGE_WARN,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   true,
			})
		}
	}()

	g.Go(func() error {
		s.State = servers.SERVER_STATE_RUNNING
		switch s.Protocol {
		case servers.SERVER_PROTOCOL_HTTP:
			return s.Transport.(*http.Server).ListenAndServe()
		case servers.SERVER_PROTOCOL_HTTPS, servers.SERVER_PROTOCOL_HTTP2:
			return s.Transport.(*http.Server).ListenAndServeTLS(s.x509Cert, s.x509Key)
		default:
			return fmt.Errorf("could not start HTTP server, invalid protocol %d, %s", s.Protocol, servers.GetStateString(s.Protocol))
		}
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			s.State = servers.SERVER_STATE_ERROR
			return fmt.Errorf("there was an error with the %s server on %s:%d %s", s.GetProtocolString(), s.Interface, s.Port, err.Error())
		}
	}
	return nil
}

// Status enumerates if the server is currently running or stopped and returns the value as a string
func (s *Server) Status() int {
	return s.State
}

// This function stops the HTTP3 server
func (s *Server) Stop() error {
	err := s.Transport.(*http.Server).Shutdown(context.Background())
	if err != nil {
		return fmt.Errorf("there was an error stopping the HTTP server:\r\n%s", err.Error())
	}
	s.State = servers.SERVER_STATE_CLOSED
	return nil
}
