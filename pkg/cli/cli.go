// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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

package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/menu"
)

// Global Variables
var clientID = uuid.NewV4()

// Shell is the exported function to start the command line interface
func Shell() {
	osSignalHandler()
	printUserMessage()
	registerMessageChannel()
	getUserMessages()

	var err error
	core.Prompt, err = readline.NewEx(&readline.Config{
		Prompt:              "\033[31mMerlin»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error creating the CLI prompt: %s", err.Error()),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		core.Exit()
	}

	defer func() {
		err := core.Prompt.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	log.SetOutput(core.Prompt.Stderr())
	menu.Set(menu.MAIN)

	for {
		// Read command line input
		line, err := core.Prompt.Readline()

		// Handle Ctrl+C
		if err == readline.ErrInterrupt {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		} else if err == io.EOF {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		}

		line = strings.TrimSpace(line)
		cmd, err := shellwords.Parse(line)
		if err != nil {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing command line arguments:\r\n%s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}

		if len(cmd) > 0 {
			menu.Handle(cmd)
		}
	}
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func registerMessageChannel() {
	um := messages.Register(clientID)
	if um.Error {
		core.MessageChannel <- um
		return
	}
	if core.Debug {
		core.MessageChannel <- um
	}
}

func getUserMessages() {
	go func() {
		for {
			core.MessageChannel <- messages.GetMessageForClient(clientID)
		}
	}()
}

// printUserMessage is used to print all messages to STDOUT for command line clients
func printUserMessage() {
	go func() {
		for {
			m := <-core.MessageChannel
			switch m.Level {
			case messages.Info:
				fmt.Println(color.CyanString("\n[i] %s", m.Message))
			case messages.Note:
				fmt.Println(color.YellowString("\n[-] %s", m.Message))
			case messages.Warn:
				fmt.Println(color.RedString("\n[!] %s", m.Message))
			case messages.Debug:
				if core.Debug {
					fmt.Println(color.RedString("\n[DEBUG] %s", m.Message))
				}
			case messages.Success:
				fmt.Println(color.GreenString("\n[+] %s", m.Message))
			case messages.Plain:
				fmt.Println("\n" + m.Message)
			default:
				fmt.Println(color.RedString("\n[_-_] Invalid message level: %d\r\n%s", m.Level, m.Message))
			}
		}
	}()
}

// osSignalHandler catches SIGINT and SIGTERM signals to prevent accidentally quitting the server when Ctrl-C is pressed
func osSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	}()
}
