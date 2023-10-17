// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2023  Russel Van Tuyl

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

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/cli/services/cli"
)

func main() {
	version := flag.Bool("version", false, "Print the version number and exit")
	flag.Parse()

	if *version {
		fmt.Printf("Merlin Version: %s, Build: %s\n", merlin.Version, merlin.Build)
		return
	}

	// Start Merlin Command Line Interface
	cliService := cli.NewCLIService()
	cliService.Run("127.0.0.1:50051")
}
