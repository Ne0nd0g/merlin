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

package opaque

import (
	// Standard
	"fmt"

	"sync"
	"time"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
	"github.com/Ne0nd0g/merlin/pkg/server/jobs"
)

// key is the Opaque server-side key
var key = gopaque.CryptoDefault.NewKey(nil)

// out is a map where the Agent ID is the key and value is an outgoing opaque.Opaque message
var out = sync.Map{}

// Handler accepts incoming Opaque Registration or Authentication messages and processes them
func Handler(agentID uuid.UUID, o opaque.Opaque) (err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.Handler() function for agent %s...", agentID))
	}
	if core.Verbose {
		logging.Message("note", fmt.Sprintf("Received OPAQUE message type: %d for agent %s", o.Type, agentID))
	}

	var opq opaque.Opaque
	switch o.Type {
	case opaque.RegInit:
		opq, err = registrationInit(agentID, o, key)
	case opaque.RegComplete:
		opq, err = registrationComplete(agentID, o)
	case opaque.AuthInit:
		opq, err = authenticateInit(agentID, o)
	case opaque.AuthComplete:
		err = authenticateComplete(agentID, o)
		if err != nil {
			return
		}

		// Add AgentInfo job
		_, err = jobs.Add(agentID, "agentInfo", []string{})
		if err != nil {
			logging.Message("warn", fmt.Sprintf("there was an error adding the agentInfo job:\r\n%s", err))
		}
		// Remove from the map
		out.Delete(agentID)
	case opaque.ReAuthenticate:
		opq, err = reAuthenticate(agentID)
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for un authenticated handler: %d", o.Type))
	}
	if err != nil {
		return
	}

	out.Store(agentID, opq)

	if core.Debug {
		logging.Message("debug", "Leaving opaque.Handler() function without error")
	}
	return
}

// registrationInit is used to register an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func registrationInit(agentID uuid.UUID, o opaque.Opaque, opaqueServerKey kyber.Scalar) (opaque.Opaque, error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.registrationInit() function for agent %s...", agentID))
	}

	logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration initialization from %s", agentID))

	returnMessage, opaqueServer, err := opaque.ServerRegisterInit(agentID, o, opaqueServerKey)
	if err != nil {
		return opaque.Opaque{}, err
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		return opaque.Opaque{}, fmt.Errorf("unable to complete OAPQUE regestration initialization because the %s agent does not exist", agentID)
	}
	agent.OPAQUE = opaqueServer
	agent.Log("Received agent OPAQUE register initialization message")

	if core.Debug {
		logging.Message("debug", "Leaving opaque.registrationInit() function without error")
	}

	return returnMessage, nil
}

// registrationComplete is used to complete OPAQUE user registration and store the encrypted envelope EnvU
func registrationComplete(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.registrationComplete function for agent %s...", agentID))
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
		logging.Message("debug", "Leaving opaque.registrationComplete function without error")
	}

	return returnMessage, nil
}

// authenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol and pre-shared key
func authenticateInit(agentID uuid.UUID, o opaque.Opaque) (opaque.Opaque, error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.authenticateInit function for agent %s...", agentID))
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent does not exist and must re-register itself
		m := fmt.Sprintf("Un-Registered agent %s sent OPAQUE authentication, instructing agent to OPAQUE register", agentID)
		logging.Message("note", m) // TODO Should use messages API
		return opaque.Opaque{Type: opaque.ReRegister}, nil
	}

	returnMessage, err := opaque.ServerAuthenticateInit(o, agent.OPAQUE)
	if err != nil {
		return opaque.Opaque{}, err
	}

	agents.Agents[agentID].Secret = []byte(agent.OPAQUE.Kex.SharedSecret.String())

	agent.Log("Received new agent OPAQUE authentication initialization message")

	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Received new agent OPAQUE authentication for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		logging.Message("debug", "Leaving opaque.authenticateInit function without error")
		logging.Message("debug", fmt.Sprintf("Server OPAQUE key exchange shared secret: %v", agents.Agents[agentID].Secret))
	}
	return returnMessage, nil
}

// authenticateComplete is used to receive the OPAQUE UserAuthComplete
func authenticateComplete(agentID uuid.UUID, o opaque.Opaque) error {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.authenticateComplete() function for agent %s...", agentID))
	}

	// check to see if this agent is already known to the server
	agent, ok := agents.Agents[agentID]
	if !ok {
		return fmt.Errorf("%s is not a known agent", agentID)
	}

	agent.Log("Received agent OPAQUE authentication complete message")
	agent.Authenticated = true

	m := fmt.Sprintf("New authenticated agent checkin for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339))
	logging.Message("success", m)

	if core.Debug {
		logging.Message("debug", "Leaving opaque.authenticateComplete() function without error")
	}

	return opaque.ServerAuthenticateComplete(o, agent.OPAQUE)
}

// reAuthenticate is used when an agent has previously completed OPAQUE registration but needs to re-authenticate
func reAuthenticate(agentID uuid.UUID) (opaque.Opaque, error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.reAuthenticate function for agent %s...", agentID))
	}
	fmt.Printf("[DEBUG] Opaque ReAuth for %s\n", agentID)
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
		logging.Message("debug", "Leaving opaque.reAuthenticate function without error")
	}

	return returnMessage, nil
}

// Get retrieves any outgoing opaque.Opaque message for the agent
func Get(agentID uuid.UUID) opaque.Opaque {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("Entering into opaque.Get function for agent %s...", agentID))
	}

	o, ok := out.LoadAndDelete(agentID)
	if !ok {
		return opaque.Opaque{}
	}

	if core.Debug {
		logging.Message("debug", "Leaving opaque.Get function without error")
	}

	return o.(opaque.Opaque)
}
