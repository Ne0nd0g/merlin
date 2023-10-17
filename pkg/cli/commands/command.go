/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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

package commands

import (
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	// 3rd Party
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"

	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
)

type Command interface {
	// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
	// Errors are not returned to ensure the CLI is not interrupted.
	// Errors are logged and can be viewed by enabling debug output in the CLI
	Completer(m menu.Menu, id uuid.UUID) readline.PrefixCompleterInterface
	// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
	// m, an optional parameter, is the Menu the command was executed from
	// id, an optional parameter, used to identify a specific Agent, Listener, or Module
	// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
	// command itself passed into command for processing
	// Errors are returned through the Error and Message fields of the embedded messages.UserMessage struct in the Response struct
	Do(m menu.Menu, id uuid.UUID, arguments string) (response Response)
	// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
	Help(m menu.Menu) help.Help
	// Menu checks to see if the command is supported for the provided menu
	Menu(menu.Menu) bool
	// OS returns the supported operating system the command can be executed on
	OS() os.OS
	// String returns the unique name of the command as a string
	String() string
}

// Response is used to return multiple values from Command receivers
type Response struct {
	Agent     uuid.UUID
	AgentOS   os.OS
	Completer *readline.PrefixCompleterInterface
	Listener  uuid.UUID
	Menu      menu.Menu
	Message   *message.UserMessage // Message is used to display a message on the CLI; A pointer is used to allow for nil values for evaluation
	Module    uuid.UUID
	Prompt    string
}
