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

package createprocess

import (
	// Standard
	"encoding/base64"
	"fmt"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/shellcode"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	// 1. Shellcode
	// 2. SpawnTo
	// 3. Arguments
	if len(options) != 3 {
		return nil, fmt.Errorf("3 arguments were expected, %d were provided", len(options))
	}
	sc, err := shellcode.ParseShellcode(options["shellcode"])
	if err != nil {
		return nil, err
	}
	return []string{"CreateProcess", base64.StdEncoding.EncodeToString(sc), options["spawnto"], options["args"]}, nil
}
