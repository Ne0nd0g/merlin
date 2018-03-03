// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2018  Russel Van Tuyl

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
	"path/filepath"
	"strconv"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/servers/http2"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/cli"
	"github.com/Ne0nd0g/merlin/pkg"
)

// Global Variables
var build = "nonRelease"

func main() {
	logging.Server("Starting Merlin Server")

	flag.BoolVar(&core.Verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&core.Debug, "debug", false, "Enable debug output")
	port := flag.Int("p", 443, "Merlin Server Port")
	ip := flag.String("i", "0.0.0.0", "The IP address of the interface to bind to")
	crt := flag.String("x509cert", filepath.Join(string(core.CurrentDir), "data", "x509", "server.crt"),
		"The x509 certificate for the HTTPS listener")
	key := flag.String("x509key", filepath.Join(string(core.CurrentDir), "data", "x509", "server.key"),
		"The x509 certificate key for the HTTPS listener")
	flag.Usage = func() {
		color.Blue("#################################################")
		color.Blue("#\t\tMERLIN SERVER\t\t\t#")
		color.Blue("#################################################")
		color.Blue("Version: " + merlin.Version + " Build: " + build)
		flag.PrintDefaults()
	}
	flag.Parse()

	color.Blue(banner.Banner1)
	color.Blue("\t\t   Version: %s", merlin.Version)
	color.Blue("\t\t   Build: %s", build)

	go http2.StartListener(strconv.Itoa(*port), *ip, *crt, *key, "/")
	cli.Shell()
}

// TODO Add session ID
// TODO add job and its ID to the channel immediately after input
// TODO add warning for using distributed TLS cert
// TODO change default useragent from Go-http-client/2.0
// TODO add CSRF tokens
// TODO check if agentLog exists even outside of InitialCheckIn
// TODO readline for file paths to use with upload
// TODO handle file names containing a space for upload/download
