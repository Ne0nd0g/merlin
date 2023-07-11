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
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/chzyer/readline"
	uuid "github.com/satori/go.uuid"
)

var pkg = "pkg/cli/commands/command.go"

type Command interface {
	Completer(id uuid.UUID) (readline.PrefixCompleterInterface, error)
	Description() string
	Do(arguments string) (message messages.UserMessage)
	DoID(id uuid.UUID, arguments string) (message messages.UserMessage)
	// Menu checks to see if the command is supported for the provided menu
	Menu(menu.Menu) bool
	String() string
	Usage() string
}
