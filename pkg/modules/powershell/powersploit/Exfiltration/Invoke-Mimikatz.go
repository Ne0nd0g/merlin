// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2017  Russel Van Tuyl

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

package Exfiltration

import (
	"github.com/ne0nd0g/merlin/pkg/modules"
)

var module = modules.Module{
	Name:     "Invoke-Mimikatz",
	Author:   append("Joe Bialek", "Benjamin DELPY `gentilkiwi`"),
	Path:     "PowerSploit/Exfiltration/Invoke-Mimikatz.ps1",
	Platform: "windows",
	Arch:     "amd64",
	Lang:     "powershell",
	Notes:    "",
}

// Options is structure containing options that can be set for the module
type Options struct {
	Module    modules.Module
	Command   []string
	Arguments string
}

func (o Options) check() bool {

	return true
}

func main() *Options {
	o := Options{
		Command:   append("DumpCreds", "DumpCerts", "Command", "ComputerName"),
		Module:    module,
		Arguments: "",
	}
	return o
}
