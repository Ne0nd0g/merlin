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

package core

import (
	// Standard
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/logging"
)

// Prompt is the command line interface prompt object
var Prompt *readline.Instance

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
	//fmt.Print(color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)))
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

// DisplayTable writes arbitrary data rows to STDOUT
func DisplayTable(header []string, rows [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)

	if len(header) > 0 {
		table.SetHeader(header)
	}

	table.AppendBulk(rows)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// ExecuteCommand runs commands on the host operating system where the CLI is being used
func ExecuteCommand(name string, arg []string) {

	cmd := exec.Command(name, arg...) // #nosec G204 Users can execute any arbitrary command by design

	out, err := cmd.CombinedOutput()

	MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Executing system command...",
		Time:    time.Time{},
		Error:   false,
	}
	if err != nil {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: err.Error(),
			Time:    time.Time{},
			Error:   true,
		}
	} else {
		MessageChannel <- messages.UserMessage{
			Level:   messages.Success,
			Message: string(out),
			Time:    time.Time{},
			Error:   false,
		}
	}
}

// Exit will prompt the user to confirm if they want to exit
func Exit() {
	color.Red("[!]Quitting...")
	logging.Server("Shutting down Merlin due to user input")
	os.Exit(0)
}
