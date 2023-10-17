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

// Package completer contains functions that query the API to get a list of values for command line tab completion
package completer

import (
	// 3rd Party
	"github.com/Ne0nd0g/merlin/pkg/cli/services/rpc"
	uuid "github.com/satori/go.uuid"
)

// AgentListCompleter returns a list of agents that exist and is used for command line tab completion
func AgentListCompleter() func(string) []string {
	return func(line string) []string {
		// The error is ignored to not disrupt the CLI; an empty list is OK
		agents, _ := rpc.GetAgents()
		var a []string
		for _, agent := range agents {
			a = append(a, agent.String())
		}
		return a
	}
}

// AgentListCompleterAll returns a list of agents that exist and is used for command line tab completion plus the special
// value of "all" to indicate all agents
func AgentListCompleterAll() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		a = append(a, "all")
		agentList, err := rpc.GetAgents()
		// If there is an error, return empty so this doesn't break the CLI
		if err != nil {
			return a
		}
		for _, id := range agentList {
			a = append(a, id.String())
		}
		return a
	}
}

// AgentLinkCompleter returns a list of child Agent IDs for the current Agent and is used for command line tab completion
func AgentLinkCompleter(id uuid.UUID) func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		links, _ := rpc.GetAgentLinks(id)
		for _, link := range links {
			a = append(a, link.String())
		}
		return a
	}
}

// GroupListCompleter returns a list of group names for command line tab completion
func GroupListCompleter() func(string) []string {
	return func(line string) []string {
		return rpc.Groups()
	}
}

// ListenerTypesCompleter returns a completer function that has a slice of all available listener types
func ListenerTypesCompleter() func(string) []string {
	comp := func(line string) []string {
		l := make([]string, 0)
		types := rpc.Servers()
		for _, t := range types {
			l = append(l, t)
		}
		return l
	}
	return comp
}

func ListenerListCompleter() func(string) []string {
	return func(line string) []string {
		msg, ids := rpc.ListenerGetIDs()
		if msg.Error() {
			return []string{}
		}
		return ids
	}
}

// ListCompleter returns a completer function for the provided input slice.
// This is commonly used with configurable listener options for command line tab completion
func ListCompleter(options []string) func(string) []string {
	return func(line string) []string {
		return options
	}
}

// ModuleCompleter returns a completer function that has a slice of all available modules
func ModuleCompleter() func(string) []string {
	return func(line string) []string {
		_, mods := rpc.GetModuleList()
		return mods
	}
}
