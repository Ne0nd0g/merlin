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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// newHTTP1 is a factory to create an HTTP/1.1 server object that implements the Server interface
// All arguments are taken in as strings and are converted/validated
func newHTTP1(options map[string]string) (Server, error) {
	var s Server
	s.id = uuid.NewV4()
	var certificates *tls.Certificate
	var err error
	proto := strings.ToLower(options["Protocol"])

	// Verify protocol match
	if proto != "http" && proto != "https" && proto != "http2" {
		return s, fmt.Errorf("server protocol mismatch, expected: http, https, or http2 got: %s", proto)
	}
	switch proto {
	case "http":
		s.protocol = servers.HTTP
	case "https":
		s.protocol = servers.HTTPS
	case "http2":
		s.protocol = servers.HTTP2
	}

	// Convert port to integer from string
	s.port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	// Verify X509 Key file exists and can be parsed
	if s.protocol == servers.HTTPS || s.protocol == servers.HTTP2 {
		certificates, err = GetTLSCertificates(options["X509Cert"], options["X509Key"])
		if err != nil {
			m := fmt.Sprintf("Certificate was not found at: %s\r\n", options["X509Cert"])
			m += "Creating in-memory x.509 certificate used for this session only"
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.Note,
				Message: m,
				Time:    time.Now().UTC(),
				Error:   false,
			})
			// Generate in-memory certificates
			certificates, err = GenerateTLSCert(nil, nil, nil, nil, nil, nil, true)
			if err != nil {
				return s, err
			}
			// Leave empty to force the use of the server's TLSConfig
			s.x509Cert = ""
			s.x509Key = ""
		} else {
			s.x509Cert = options["X509Cert"]
			s.x509Key = options["X509Key"]
		}
		insecure, errI := CheckInsecureFingerprint(*certificates)
		if errI != nil {
			return s, errI
		}
		if insecure {
			m := fmt.Sprintf("Insecure publicly distributed Merlin x.509 testing certificate in use for %s server on %s:%s\r\n", proto, options["Interface"], options["Port"])
			m += "Additional details: https://merlin-c2.readthedocs.io/en/latest/server/x509.html"
			messages.SendBroadcastMessage(messages.UserMessage{
				Level:   messages.Warn,
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
		return s, fmt.Errorf("a Pre-Shared Key (PSK) password must be provided")
	}

	if _, ok := options["JWTKey"]; !ok {
		return s, fmt.Errorf("A JWT Key must be provided")
	}

	// Key must be 32 bytes
	jwt, err := base64.StdEncoding.DecodeString(options["JWTKey"])
	if err != nil {
		return s, fmt.Errorf("there was an error base64 decoding the provided JWT Key %s: %s", options["JWTKey"], err)
	}
	if len(jwt) != 32 {
		return s, fmt.Errorf("the provided JWT key was %d bytes but must be 32 bytes", len(jwt))
	}

	// TODO save JWT key for a server ID into a database
	s.handler = &handler{
		// Used to sign and encrypt JWT
		listener: s.id,
		jwtKey:   jwt,
		psk:      []byte(options["PSK"]),
	}

	// Add handler with context
	for _, url := range s.urls {
		mux.HandleFunc(url, s.handler.agentHandler)
	}

	s.transport = &http.Server{
		Addr:              options["Interface"] + ":" + options["Port"],
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Add X.509 certificates if using TLS
	if s.protocol == servers.HTTPS || s.protocol == servers.HTTP2 {
		s.transport.(*http.Server).TLSConfig = &tls.Config{Certificates: []tls.Certificate{*certificates}} // #nosec G402 TLS version is not configured to facilitate dynamic JA3 configurations
	}

	s.iface = options["Interface"]
	s.state = Stopped
	return s, nil
}
