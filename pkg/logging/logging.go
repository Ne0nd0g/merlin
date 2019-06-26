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

package logging

import (
	// Standard
	"fmt"
	"os"
	"path/filepath"
	"time"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
)

var serverLog *os.File

func init() {

	// Server Logging
	if _, err := os.Stat(filepath.Join(core.CurrentDir, "data", "log", "merlinServerLog.txt")); os.IsNotExist(err) {
		errM := os.MkdirAll(filepath.Join(core.CurrentDir, "data", "log"), 0750)
		if errM != nil {
			message("warn", "there was an error creating the log directory")
		}
		serverLog, errC := os.Create(filepath.Join(core.CurrentDir, "data", "log", "merlinServerLog.txt"))
		if errC != nil {
			message("warn", "there was an error creating the merlinServerLog.txt file")
			return
		}
		// Change the file's permissions
		errChmod := serverLog.Chmod(0640)
		if errChmod != nil {
			message("warn", fmt.Sprintf("there was an error changing the file permissions for the agent log:\r\n%s", errChmod.Error()))
		}
		if core.Debug {
			message("debug", fmt.Sprintf("Created server log file at: %s\\data\\log\\merlinServerLog.txt", core.CurrentDir))
		}
	}

	var errLog error
	serverLog, errLog = os.OpenFile(filepath.Join(core.CurrentDir, "data", "log", "merlinServerLog.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if errLog != nil {
		message("warn", "there was an error with the Merlin Server log file")
		message("warn", errLog.Error())
	}
}

// Server writes a log entry into the server's log file
func Server(logMessage string) {
	_, err := serverLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), logMessage))
	if err != nil {
		message("warn", "there was an error writing to the Merlin Server log file")
	}
}

// Message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

// TODO configure all message to be displayed on the CLI to be returned as errors and not written to the CLI here
