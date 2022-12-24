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
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	// X Packages
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/servers"
)

// newHTTP2 is a factory to create an HTTP/2 server object that implements the Server interface
// All arguments are taken in as strings and are converted/validated
func newHTTP2(options map[string]string) (Server, error) {
	var s Server
	var err error

	// Verify protocol match
	if strings.ToLower(options["Protocol"]) != "h2c" {
		return s, fmt.Errorf("server protocol mismatch, expected: H2C got: %s", options["Protocol"])
	}
	s.protocol = servers.H2C

	// Convert port to integer from string
	s.port, err = strconv.Atoi(options["Port"])
	if err != nil {
		return s, fmt.Errorf("there was an error converting the port number to an integer: %s", err.Error())
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

	h2s := &http2.Server{}
	s.transport = &http.Server{
		Addr:              options["Interface"] + ":" + options["Port"],
		Handler:           h2c.NewHandler(mux, h2s),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.iface = options["Interface"]
	s.id = uuid.NewV4()
	s.state = Stopped

	return s, nil
}
