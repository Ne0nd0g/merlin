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
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// newHTTP3 is a factory to create an HTTP/3 server object that implements the Server interface
// All arguments are taken in as strings and are converted/validated
func newHTTP3(options map[string]string) (Server, error) {
	var s Server
	var certificates *tls.Certificate
	var err error

	// Verify protocol match
	if strings.ToLower(options["Protocol"]) != "http3" {
		return s, fmt.Errorf("server protocol mismatch, expected: HTTP3 got: %s", options["Protocol"])
	}
	s.protocol = servers.HTTP3

	// Convert port to integer from string
	s.port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
	}

	// Verify X509 Key file exists and can be parsed
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
		return s, fmt.Errorf("a Pre-Shared Key (PSK) password must be provided")
	}

	// TODO save JWT key for a server ID into a database
	h := handler{
		// Used to sign and encrypt JWT
		jwtKey: []byte(core.RandStringBytesMaskImprSrc(32)),
		psk:    []byte(options["PSK"]),
	}

	// Add handler with context
	for _, url := range s.urls {
		mux.HandleFunc(url, h.agentHandler)
	}

	s.transport = &http3.Server{
		Addr:           options["Interface"] + ":" + options["Port"],
		Port:           s.port,
		Handler:        mux,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{*certificates}, MinVersion: tls.VersionTLS12},
		QuicConfig: &quic.Config{
			// Opted for a long timeout to prevent the client from sending a HTTP/2 PING Frame
			MaxIdleTimeout:  time.Until(time.Now().AddDate(0, 42, 0)),
			KeepAlivePeriod: time.Second * 0,
		},
	}

	s.iface = options["Interface"]
	s.id = uuid.NewV4()
	s.state = Stopped

	return s, nil
}
