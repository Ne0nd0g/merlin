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

package opaque

import (
	// Standard
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/google/uuid"
	"go.dedis.ch/kyber/v3"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/opaque"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	opaque2 "github.com/Ne0nd0g/merlin/v2/pkg/opaque"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/job"
)

// key is the Opaque server-side key
var key = gopaque.CryptoDefault.NewKey(nil)

// servers is a map where the Agent ID is the key and the value is the opaque server
// Stored here until the agent is full authenticated, added to the agent structure, and then removed from the map
var servers = sync.Map{}

// out is a map where the Agent ID is the key and value is an outgoing opaque.Opaque message
var out = sync.Map{}

// Authenticator is a structure that holds an Agent service to add agents once they've completed authentication
type Authenticator struct {
	agentService *agent.Service
	jobService   *job.Service
}

// NewAuthenticator is a factory to create and return an OPAQUE authenticator that implements the Authenticator interface
func NewAuthenticator() (*Authenticator, error) {
	var err error
	var auth Authenticator
	auth.agentService = agent.NewAgentService()
	auth.jobService = job.NewJobService()
	return &auth, err
}

// Authenticate is an OPAQUE message handler and the entry point function to authenticate an Agent
// Accepts incoming Opaque Registration or Authentication messages and processes them
func (a *Authenticator) Authenticate(id uuid.UUID, data interface{}) (msg messages.Base, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "ID", id, "data type", fmt.Sprintf("%T", data))
	defer slog.Log(context.Background(), logging.LevelTrace, "leaving function", "msg", msg, "Error", err)

	// Verify the data interface is the opaque.Opaque type
	switch data.(type) {
	case opaque.Opaque:
		// Do nothing
		slog.Debug("Received OPAQUE message", "OPAQUE type", data.(opaque.Opaque).Type, "Agent", id)
	default:
		// If no Opaque data is passed in, assume the Agent needs to re-authenticate
		data = opaque.Opaque{
			Type:    opaque.ReAuthenticate,
			Payload: nil,
		}
	}

	var opq opaque.Opaque
	o := data.(opaque.Opaque)
	switch o.Type {
	case opaque.RegInit:
		opq, err = a.registrationInit(id, o, key)
	case opaque.RegComplete:
		opq, err = a.registrationComplete(id, o)
	case opaque.AuthInit:
		opq, err = a.authenticateInit(id, o)
	case opaque.AuthComplete:
		err = a.authenticateComplete(id, o)
		if err != nil {
			return
		}

		// Add AgentInfo job
		_, err = a.jobService.Add(id, "agentInfo", []string{})
		if err != nil {
			slog.Warn(fmt.Sprintf("there was an error adding the agentInfo job:\r\n%s", err))
		}
		// Remove from the map
		out.Delete(id)
		msg.ID = id
		msg.Type = messages.IDLE
		return
	case opaque.ReAuthenticate:
		opq, err = a.reAuthenticate(id)
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for un authenticated handler: %d", o.Type))
	}

	msg.ID = id
	msg.Type = messages.OPAQUE
	msg.Payload = opq
	return
}

// registrationInit is used to register an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func (a *Authenticator) registrationInit(agentID uuid.UUID, o opaque.Opaque, opaqueServerKey kyber.Scalar) (opaque.Opaque, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "ID", agentID, "opaque", o, "opaqueServerKey", opaqueServerKey)
	defer slog.Log(context.Background(), logging.LevelTrace, "leaving function")
	slog.Debug(fmt.Sprintf("Received new agent OPAQUE user registration initialization from %s", agentID))

	returnMessage, opaqueServer, err := opaque2.ServerRegisterInit(agentID, o, opaqueServerKey)
	if err != nil {
		return opaque.Opaque{}, err
	}

	servers.Store(agentID, opaqueServer)

	if core.Debug {
		slog.Debug("Leaving opaque.registrationInit() function without error")
	}

	return returnMessage, nil
}

// registrationComplete is used to complete OPAQUE user registration and store the encrypted envelope EnvU
func (a *Authenticator) registrationComplete(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		slog.Debug(fmt.Sprintf("Entering into opaque.registrationComplete function for agent %s...", agentID))
	}

	opaqueServer, ok := servers.LoadAndDelete(agentID)
	if !ok {
		return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.registrationComplete(): unable to find Opaque Server structure for agent %s", agentID)
	}
	returnMessage, err := opaque2.ServerRegisterComplete(agentID, o, opaqueServer.(*opaque2.Server))
	if err != nil {
		return opaque.Opaque{}, err
	}

	thisAgent, err := a.agentService.Agent(agentID)
	// If the error is not nil, continue on and create a new agent
	if err == nil {
		// if the error is nil, the agent already exists and likely re-registering and the Agent doesn't need to be created
		thisAgent.UpdateOPAQUE(opaqueServer.(*opaque2.Server))
		thisAgent.UpdateStatusCheckin(time.Now().UTC())
		err = a.agentService.Update(thisAgent)
		if err != nil {
			return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.registrationComplete(): error updating agent %s: %s", agentID, err)
		}
		thisAgent.Log("OPAQUE registration complete")
		return returnMessage, nil
	}

	// After successful registration, create the agent
	// Want to add it now for future support when the agent doesn't need to register and the registration data is already in a database
	newAgent, err := agents.NewAgent(agentID, []byte{}, opaqueServer.(*opaque2.Server), time.Now().UTC())
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.registrationComplete(): unable to create a new agent for %s: %s", agentID, err)
	}

	err = a.agentService.Add(newAgent)
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.registrationComplete(): error storing agent %s: %s", agentID, err)
	}

	newAgent.Log("OPAQUE registration complete")

	if core.Debug {
		slog.Debug("Leaving opaque.registrationComplete function without error")
	}

	return returnMessage, nil
}

// authenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol and pre-shared key
func (a *Authenticator) authenticateInit(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		slog.Debug(fmt.Sprintf("Entering into opaque.authenticateInit function for agent %s...", agentID))
	}

	thisAgent, err := a.agentService.Agent(agentID)
	if err != nil {
		// Agent does not exist and must re-register itself
		slog.Warn(fmt.Sprintf("Un-Registered agent %s sent OPAQUE authentication, instructing agent to OPAQUE register", agentID))
		return opaque.Opaque{Type: opaque.ReRegister}, nil
	} else if thisAgent.OPAQUE() == nil {
		slog.Warn(fmt.Sprintf("registration information for Agent %s is empty, instructing agent to OPAQUE register", agentID))
		return opaque.Opaque{Type: opaque.ReRegister}, nil
	}

	returnMessage, err := opaque2.ServerAuthenticateInit(o, thisAgent.OPAQUE())
	if err != nil {
		return opaque.Opaque{}, err
	}

	keys := []byte(thisAgent.OPAQUE().Kex.SharedSecret.String())

	newAgent, err := agents.NewAgent(agentID, keys, thisAgent.OPAQUE(), thisAgent.Initial())
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.authenticateInit(): unable to create a new agent for %s: %s", agentID, err)
	}

	err = a.agentService.Update(newAgent)
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("pkg/authenticaters/opaque.authenticateInit(): error storing agent %s: %s", agentID, err)
	}

	thisAgent.Log("Received new agent OPAQUE authentication initialization message")

	if core.Debug {
		slog.Debug(fmt.Sprintf("Received new agent OPAQUE authentication for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		slog.Debug("Leaving opaque.authenticateInit function without error")
		slog.Debug(fmt.Sprintf("Server OPAQUE key exchange shared secret: %x", keys))
	}
	return returnMessage, nil
}

// authenticateComplete is used to receive the OPAQUE UserAuthComplete
func (a *Authenticator) authenticateComplete(agentID uuid.UUID, o opaque.Opaque) error {
	if core.Debug {
		slog.Debug(fmt.Sprintf("Entering into opaque.authenticateComplete() function for agent %s...", agentID))
	}

	// check to see if this agent is already known to the server
	thisAgent, err := a.agentService.Agent(agentID)
	if err != nil {
		return fmt.Errorf("pkg/authenticaters/opaque.authenticateComplete(): %s", err)
	}

	thisAgent.Log("Received agent OPAQUE authentication complete message")
	err = a.agentService.UpdateAuthenticated(agentID, true)
	if err != nil {
		return err
	}

	err = a.agentService.UpdateAlive(agentID, true)
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("New authenticated agent checkin for %s", agentID))

	if core.Debug {
		slog.Debug("Leaving opaque.authenticateComplete() function without error")
	}

	return opaque2.ServerAuthenticateComplete(o, thisAgent.OPAQUE())
}

// reAuthenticate is used when an agent has previously completed OPAQUE registration but needs to re-authenticate
func (a *Authenticator) reAuthenticate(agentID uuid.UUID) (opaque.Opaque, error) {
	if core.Debug {
		slog.Debug(fmt.Sprintf("Entering into opaque.reAuthenticate function for agent %s...", agentID))
	}
	returnMessage := opaque.Opaque{
		Type: opaque.ReAuthenticate,
	}

	thisAgent, err := a.agentService.Agent(agentID)
	if err != nil {
		// Agent does not exist and must re-register itself
		returnMessage.Type = opaque.ReRegister
		return returnMessage, nil
	} else if thisAgent.OPAQUE() == nil {
		// Agent's OPAQUE registration information is empty or reset and must re-register itself
		returnMessage.Type = opaque.ReRegister
		return returnMessage, nil
	}

	thisAgent.Log("Instructing agent to re-authenticate with OPAQUE protocol")

	if core.Debug {
		slog.Debug("Leaving opaque.reAuthenticate function without error")
	}

	return returnMessage, nil
}

// String returns the name of authenticator type
func (a *Authenticator) String() string {
	return "OPAQUE"
}
