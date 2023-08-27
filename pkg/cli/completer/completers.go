// Package completer contains functions that query the API to get a list of values for command line tab completion
package completer

import (
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	uuid "github.com/satori/go.uuid"
)
import listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"

// AgentListCompleter returns a list of agents that exist and is used for command line tab completion
func AgentListCompleter() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		agentList := agentAPI.GetAgents()
		for _, id := range agentList {
			a = append(a, id.String())
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
		agentList := agentAPI.GetAgents()
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
		links, _ := agentAPI.GetAgentLinks(id)
		for _, link := range links {
			a = append(a, link.String())
		}
		return a
	}
}

// GroupListCompleter returns a list of group names for command line tab completion
func GroupListCompleter() func(string) []string {
	return func(line string) []string {
		return agentAPI.GroupListNames()
	}
}

func ListenerListCompleter() func(string) []string {
	return func(line string) []string {
		l := make([]string, 0)
		ids := listenerAPI.GetListenerIDs()
		for _, id := range ids {
			l = append(l, id.String())
		}
		return l
	}
}

// ListCompleter returns a completer function for the provided input slice.
// This is commonly used with configurable listener options for command line tab completion
func ListCompleter(options []string) func(string) []string {
	return func(line string) []string {
		return options
	}
}
