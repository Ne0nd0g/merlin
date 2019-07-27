// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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

package main

import (
	// Standard
	"flag"
	"fmt"
	"os"
	"path/filepath"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/servers/http2"
)

// Global Variables
var build = "nonRelease"
var psk = "merlin"

func main() {
	logging.Server("Starting Merlin Server version " + merlin.Version + " build " + merlin.Build)

	flag.BoolVar(&core.Verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&core.Debug, "debug", false, "Enable debug output")
	port := flag.Int("p", 443, "Merlin Server Port")
	ip := flag.String("i", "127.0.0.1", "The IP address of the interface to bind to")
	proto := flag.String("proto", "h2", "Protocol for the agent to connect with [h2, hq]")
	crt := flag.String("x509cert", filepath.Join(string(core.CurrentDir), "data", "x509", "server.crt"),
		"The x509 certificate for the HTTPS listener")
	key := flag.String("x509key", filepath.Join(string(core.CurrentDir), "data", "x509", "server.key"),
		"The x509 certificate key for the HTTPS listener")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	flag.Usage = func() {
		color.Blue("#################################################")
		color.Blue("#\t\tMERLIN SERVER\t\t\t#")
		color.Blue("#################################################")
		color.Blue("Version: " + merlin.Version)
		color.Blue("Build: " + build)
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	color.Blue(banner.MerlinBanner1)
	color.Blue("\t\t   Version: %s", merlin.Version)
	color.Blue("\t\t   Build: %s", build)

	// Start Merlin Command Line Interface
	go cli.Shell()

	// Start Merlin Server to listen for agents
	server, err := http2.New(*ip, *port, *proto, *key, *crt, psk)
	if err != nil {
		color.Red(fmt.Sprintf("[!]There was an error creating a new server instance:\r\n%s", err.Error()))
		os.Exit(1)
	} else {
		err := server.Run()
		if err != nil {
			color.Red(fmt.Sprintf("[!]There was an error starting the server:\r\n%s", err.Error()))
			os.Exit(1)
		}
	}
}

// TODO add CSRF tokens
// TODO check if agentLog exists even outside of InitialCheckIn
// TODO readline for file paths to use with upload
// TODO handle file names containing a space for upload/download
