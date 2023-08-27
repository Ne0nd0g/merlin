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

package core

import (
	// Standard
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/logging"
)

// STDOUT is a global mutex to prevent concurrent writes to STDOUT
var STDOUT sync.Mutex

// Debug puts Merlin into debug mode and displays debug messages
var Debug = false

// Verbose puts Merlin into verbose mode and displays verbose messages
var Verbose = false

// CurrentDir is the current directory where Merlin was executed from
var CurrentDir, _ = os.Getwd()

// MessageChannel is used to input user messages that are eventually written to STDOUT on the CLI application
var MessageChannel = make(chan messages.UserMessage)

// Confirm reads in a string and returns true if the string is y or yes but does not provide the prompt question
func Confirm(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)),
		Time:    time.Now().UTC(),
		Error:   false,
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error reading the input:\r\n%s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	}
	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes", "-y", "-Y"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}
	return false
}

// Exit will prompt the user to confirm if they want to exit
func Exit() {
	color.Red("[!]Quitting...")
	logging.Server("Shutting down Merlin due to user input")
	os.Exit(0)
}
