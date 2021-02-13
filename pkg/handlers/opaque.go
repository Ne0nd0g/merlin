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

package handlers

import (
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
	"github.com/Ne0nd0g/merlin/pkg/server/jobs"
)

// OPAQUEHandler processes and dispatches OPAQUE messages for authenticated agents
// Messages should only allow:
// AuthComplete
func OPAQUEHandler(agentID uuid.UUID, o opaque.Opaque) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into opaque.Handler() function...")
	}
	var err error
	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
		Type:    messages.OPAQUE,
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}
	switch o.Type {
	case opaque.AuthComplete:
		err = authenticateComplete(agentID, o)
		if err == nil {
			// Add AgentInfo job
			_, errAdd := jobs.Add(agentID, "agentInfo", []string{})
			if errAdd != nil {
				message("warn", fmt.Sprintf("there was an error adding the agentInfo job:\r\n%s", errAdd))
			}
			// Get job from queue
			jobsList, err := jobs.Get(agentID)
			if err != nil {
				message("warn", err.Error())
			} else {
				returnMessage.Type = messages.JOBS
				returnMessage.Payload = jobsList
			}
		}
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for authenticated handler: %d", o.Type))
	}
	if err != nil {
		return returnMessage, err
	}

	if core.Debug {
		message("debug", "Leaving opaque.Handler() function without error")
	}
	return returnMessage, nil
}

// OPAQUEUnAuthHandler accepts messages from an unauthenticated agent
// Messages should only allow:
// RegInit
// RegComplete
// AuthInit
func OPAQUEUnAuthHandler(agentID uuid.UUID, o opaque.Opaque, key kyber.Scalar) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into opaque.UnAuthHandler() function...")
	}
	if core.Verbose {
		message("note", fmt.Sprintf("Received OPAQUE message type: %d", o.Type))
	}
	var err error
	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
		Type:    messages.OPAQUE,
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}
	switch o.Type {
	case opaque.RegInit:
		returnMessage.Payload, err = registrationInit(agentID, o, key)
	case opaque.RegComplete:
		returnMessage.Payload, err = registrationComplete(agentID, o)
	case opaque.AuthInit:
		returnMessage.Payload, err = authenticateInit(agentID, o)
	case opaque.ReAuthenticate:
		returnMessage.Payload, err = reAuthenticate(agentID)
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for un authenticated handler: %d", o.Type))
	}
	if err != nil {
		return returnMessage, err
	}

	if core.Debug {
		message("debug", "Leaving opaque.UnAuthHandler() function without error")
	}
	return returnMessage, nil
}

// registrationInit is used to register an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func registrationInit(agentID uuid.UUID, o opaque.Opaque, opaqueServerKey kyber.Scalar) (opaque.Opaque, error) {
	// TODO Make sure isAgent() is checked before making this call
	if core.Debug {
		message("debug", "Entering into opaque.RegistrationInit() function...")
	}

	logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration initialization from %s", agentID))

	_, ok := agents.Agents[agentID]
	if ok {
		return opaque.Opaque{}, fmt.Errorf("the %s agent has already been registered", agentID)
	}

	returnMessage, opaqueServer, err := opaque.ServerRegisterInit(agentID, o, opaqueServerKey)
	if err != nil {
		return opaque.Opaque{}, err
	}

	// Create new agent and add it to the global map
	agent, agentErr := agents.New(agentID)
	if agentErr != nil {
		return returnMessage, fmt.Errorf("there was an error creating a new agent instance for %s:\r\n%s", agentID, agentErr)
	}
	agent.OPAQUE = opaqueServer

	// Add agent to global map
	agents.Agents[agentID] = &agent

	agent.Log("Received agent OPAQUE register initialization message")

	if core.Debug {
		message("debug", "Leaving agents.OPAQUERegistrationInit function without error")
	}

	return returnMessage, nil
}

// registrationComplete is used to complete OPAQUE user registration and store the encrypted envelope EnvU
func registrationComplete(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		message("debug", "Entering into handlers.registrationComplete function...")
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		return opaque.Opaque{}, fmt.Errorf("the %s agent has not completed OPAQUE user registration intialization", agentID)
	}

	returnMessage, err := opaque.ServerRegisterComplete(agentID, o, agent.OPAQUE)
	if err != nil {
		return opaque.Opaque{}, err
	}

	agent.Log("OPAQUE registration complete")

	if core.Debug {
		message("debug", "Leaving handlers.registrationComplete function without error")
	}

	return returnMessage, nil
}

// authenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol and pre-shared key
func authenticateInit(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.authenticateInit function...")
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent does not exist and must re-register itself
		m := fmt.Sprintf("Un-Registered agent %s sent OPAQUE authentication, instructing agent to OPAQUE register", agentID)
		message("note", m) // TODO Should use messages API
		return opaque.Opaque{Type: opaque.ReRegister}, nil
	}

	returnMessage, err := opaque.ServerAuthenticateInit(o, agent.OPAQUE)
	if err != nil {
		return opaque.Opaque{}, err
	}

	agents.Agents[agentID].Secret = []byte(agent.OPAQUE.Kex.SharedSecret.String())

	agent.Log("Received new agent OPAQUE authentication initialization message")

	if core.Debug {
		message("debug", fmt.Sprintf("Received new agent OPAQUE authentication for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		message("debug", "Leaving opaque.authenticateInit function without error")
		message("debug", fmt.Sprintf("Server OPAQUE key exchange shared secret: %v", agents.Agents[agentID].Secret))
	}
	return returnMessage, nil
}

// authenticateComplete is used to receive the OPAQUE UserAuthComplete
func authenticateComplete(agentID uuid.UUID, o opaque.Opaque) error {
	if core.Debug {
		message("debug", "Entering into opaque.authenticateComplete function")
	}
	m := fmt.Sprintf("New authenticated agent checkin for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339))
	message("success", m)

	// check to see if this agent is already known to the server
	agent, ok := agents.Agents[agentID]
	if !ok {
		return fmt.Errorf("%s is not a known agent", agentID)
	}

	agent.Log("Received agent OPAQUE authentication complete message")

	return opaque.ServerAuthenticateComplete(o, agent.OPAQUE)
}

// reAuthenticate is used when an agent has previously completed OPAQUE registration but needs to re-authenticate
func reAuthenticate(agentID uuid.UUID) (opaque.Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.reAuthenticate function...")
	}

	returnMessage := opaque.Opaque{
		Type: opaque.ReAuthenticate,
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent does not exist and must re-register itself
		returnMessage.Type = opaque.ReRegister
		return returnMessage, nil
	}

	agent.Log("Instructing agent to re-authenticate with OPAQUE protocol")

	if core.Debug {
		message("debug", "Leaving opaque.reAuthenticate function without error")
	}

	return returnMessage, nil
}
