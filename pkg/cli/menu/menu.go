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

package menu

import (
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
)

var handler func([]string)

const (
	// MAIN is for the main menu
	MAIN = iota
	// AGENT is for the agent menu
	AGENT
	// MODULE is for the module menu
	MODULE
	// LISTENER is for a specific, already instantiated, listener menu
	LISTENER
	// LISTENERS is for the top-level listeners menu
	LISTENERS
	// LISTENERSETUP is the menu used to configure listener options before creation
	LISTENERSETUP
)

// Handle receives commands entered on the command line and processes them to take an action
func Handle(cmd []string) {
	handler(cmd)
}

// Set configures the CLI's to use a specific menu system. Typically, used to switch between menus.
func Set(m int) {
	switch m {
	case AGENT:
		handler = handlerAgent
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32magent\033[31m][\033[33m" + agent.String() + "\033[31m]»\033[0m ")
		core.Prompt.Config.AutoComplete = completerAgent()
	case LISTENER:
		handler = handlerListener
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + listener.name + "\033[31m]»\033[0m ")
		core.Prompt.Config.AutoComplete = completerListener()
	case LISTENERS:
		handler = handlerListeners
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
		core.Prompt.Config.AutoComplete = completerListeners()
	case LISTENERSETUP:
		handler = handlerListenerSetup
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + listenerType + "\033[31m]»\033[0m ")
		core.Prompt.Config.AutoComplete = completerListenerSetup()
	case MAIN:
		handler = handlerMain
		core.Prompt.SetPrompt("\u001B[31mMerlin»\u001B[0m ")
		core.Prompt.Config.AutoComplete = completerMain()
	case MODULE:
		handler = handlerModule
		core.Prompt.SetPrompt("\033[31mMerlin[\033[32mmodule\033[31m][\033[33m" + module.Name + "\033[31m]»\033[0m ")
		core.Prompt.Config.AutoComplete = completerModule()
	default:
		handler = handlerMain
		core.Prompt.SetPrompt("\u001B[31mMerlin»\u001B[0m ")
		core.Prompt.Config.AutoComplete = completerMain()
	}
}
