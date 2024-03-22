/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	// Standard
	"flag"
	"fmt"
	"log"

	// Internal
	merlin "github.com/Ne0nd0g/merlin/v2/pkg"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/rpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "The address to listen on for client connections")
	password := flag.String("password", "merlin", "the password to for CLI RPC clients to connect to this server")
	secure := flag.Bool("secure", false, "Require client TLS certificate verification")
	tlsKey := flag.String("tlsKey", "", "TLS private key file path")
	tlsCert := flag.String("tlsCert", "", "TLS certificate file path")
	tlsCA := flag.String("tlsCA", "", "TLS Certificate Authority file path to verify client certificates")
	debug := flag.Bool("debug", false, "Enable debug logging")
	trace := flag.Bool("trace", false, "Enable trace logging")
	extra := flag.Bool("extra", false, "Enable extra debug logging")
	v := flag.Bool("version", false, "Print the version number and exit")

	var listenersStorageFile string
	flag.StringVar(&listenersStorageFile, "listenersFile", "", "YAML file, load listeners from it and saves to it.")

	flag.Parse()

	if *v {
		fmt.Printf("Merlin Version: %s, Build: %s\n", merlin.Version, merlin.Build)
		return
	}

	// Set the logging level
	if *extra {
		logging.SetLevel(logging.LevelExtraDebug)
	} else if *trace {
		logging.SetLevel(logging.LevelTrace)
	} else if *debug {
		logging.SetLevel(logging.LevelDebug)
	}

	// Get the RPC service
	service, err := rpc.NewRPCService(*password, *secure, *tlsCert, *tlsKey, *tlsCA)
	if err != nil {
		log.Fatal(err)
	}
	err = service.Run(*addr, listenersStorageFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Exiting without error")
}
