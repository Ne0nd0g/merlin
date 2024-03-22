/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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

// Package none is an empty, or nil, authenticator used to bypass authentication requirements
package none

import (
	// Standard
	"fmt"
	"log/slog"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/job"
)

// Authenticator is a structure that holds an Agent service to add agents once they've completed authentication
type Authenticator struct {
	agentService *agent.Service
	jobService   *job.Service
}

// NewAuthenticator is a factory to create and return an OPAQUE authenticator that implements the Authenticator interface
func NewAuthenticator() *Authenticator {
	var auth Authenticator
	auth.agentService = agent.NewAgentService()
	auth.jobService = job.NewJobService()
	return &auth
}

func (a *Authenticator) Authenticate(id uuid.UUID, data interface{}) (msg messages.Base, err error) {
	// Create a new Agent object
	// Agents that don't have an authentication mechanism will not have a per-agent secret and will perpetually use the
	// interface's secret
	newAgent, err := agents.NewAgent(id, []byte{}, nil, time.Now().UTC())
	if err != nil {
		return msg, fmt.Errorf("pkg/authenticaters/none.Authenticate(): there was an error getting a new Agent: %s", err)
	}
	newAgent.UpdateAuthenticated(true)
	newAgent.UpdateAlive(true)

	// Store the new Agent
	err = a.agentService.Add(newAgent)
	if err != nil {
		return
	}

	newAgent.Log("Agent successfully used NONE authentication method")
	slog.Info(fmt.Sprintf("New unauthenticated agent checkin for %s", id))

	// Add AgentInfo job
	_, err = a.jobService.Add(id, "agentInfo", []string{})
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error adding the agentInfo job for agent %s: %s", id, err))
	}

	msg.ID = id
	msg.Type = messages.IDLE
	return
}

// String returns the name of authenticator type
func (a *Authenticator) String() string {
	return "none"
}
