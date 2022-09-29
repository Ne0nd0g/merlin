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

package messages

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/listeners/lrepo"
	"math/rand"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/handlers/opaque"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	o "github.com/Ne0nd0g/merlin/pkg/opaque"
	"github.com/Ne0nd0g/merlin/pkg/server/jobs"
	"github.com/Ne0nd0g/merlin/pkg/util"
)

// init executes whenever the package is initialized
func init() {
	// Needed to ensure other "rand" functions are not static
	rand.Seed(time.Now().UTC().UnixNano())
}

// In handles & processes incoming base messages
func In(msg messages.Base) (err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("entering into handlers.messages.In() with %+v", msg))
	}
	// Validate agent is known to the server
	_, ok := agents.Agents[msg.ID]
	if !ok {
		// Create a new agent structure on the server
		agent, err := agents.New(msg.ID)
		if err != nil {
			return err
		}
		// Add newly created agent to the global Agents structure
		agents.Agents[msg.ID] = &agent
	}
	agent := agents.Agents[msg.ID]

	// Update status checkin time
	agent.StatusCheckIn = time.Now().UTC()

	// Messages from unauthenticated agents
	if !agent.Authenticated {
		if msg.Type == messages.OPAQUE {
			err = opaque.Handler(msg.ID, msg.Payload.(o.Opaque))
			return
		} else {
			err = fmt.Errorf("unhandled unauthenticated messages.Base type %s", messages.String(msg.Type))
			return
		}
	}

	// Messages from authenticated agents

	// Handle incoming message type
	switch msg.Type {
	case messages.CHECKIN:
		// Nothing to do
	case messages.JOBS:
		err = jobs.Handler(msg)
	default:
		err = fmt.Errorf("unhandled authenticated messages.Base type %s", messages.String(msg.Type))
		return
	}

	if err != nil {
		return
	}

	// Check for delegate messages for linked peer-to-peer agents
	if len(msg.Delegates) > 0 {
		delegatesIn(msg.ID, msg.Delegates)
	}

	if core.Debug {
		logging.Message("debug", "leaving handlers.messages.In() without error")
	}
	return
}

// Out gets messages ready to be sent to the agent
func Out(agentID uuid.UUID) (response messages.Base, err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("entering into handlers.messages.Out() for agent %s", agentID))
	}
	// Validate agent is known to the server
	agent, ok := agents.Agents[agentID]
	if !ok {
		err = fmt.Errorf("unable to retrieve outgoing messages for unknown agent %s", agentID)
	}

	response.ID = agentID
	response.Version = 1.0

	// If the agent is not authenticated
	if !agent.Authenticated {
		payload := opaque.Get(agentID)
		// Check to see if an empty structure was returned
		if payload.Type == 0 {
			return
		}
		response.Type = messages.OPAQUE
		response.Payload = payload
		// Prevent static OPAQUE message size
		// #nosec G404 -- Random number does not impact security
		response.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(4096))
		return response, err
	}

	// See if there are any jobs for the agent
	jobs, err := jobs.Get(agentID)
	if err != nil {
		return
	}
	if len(jobs) > 0 {
		response.Type = messages.JOBS
		response.Payload = jobs
	} else {
		response.Type = messages.IDLE
	}

	// See if there are any delegate messages for the agent
	delegates, err := delegatesOut(agentID)
	if err != nil {
		return
	}
	response.Delegates = delegates

	// Apply message padding
	pad := agent.PaddingMax
	// When agent has authenticated but hasn't sent back its initial AgentInfo structure to prevent fixed message size
	if agent.Version == "" {
		pad = 4096
	}
	if pad > 0 {
		// #nosec G404 -- Random number does not impact security
		response.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(pad))
	}
	return
}

// delegatesOut enumerates agents that are linked to the incoming agent and returns messages that belong to the linked agents
// The call is meant to be recursive for nested linked agents
func delegatesOut(agentID uuid.UUID) (delegates []messages.Delegate, err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("entering into handlers.messages.DelegatesOut() for agent %s", agentID))
	}

	agent := agents.Agents[agentID]
	agent.LinkedAgents.Range(func(k, _ any) bool {

		linkedAgent := k.(uuid.UUID)
		var response messages.Base
		response, err = Out(linkedAgent)
		if err != nil {
			return false
		}
		// Check to see if there were no return messages
		if response.Type == 0 {
			if core.Debug {
				logging.Message("debug", fmt.Sprintf("\tthere were no return messages for linked agent %s", linkedAgent))
			}
			return false
		}

		if core.Debug {
			logging.Message("debug", fmt.Sprintf("\tRecieved return delegate message %s for agent %s\n", messages.String(response.Type), response.ID))
		}

		if response.Type == messages.OPAQUE {
			if core.Debug {
				logging.Message("debug", fmt.Sprintf("\t\t[DEBUG] OPAQUE type %d (%d)\n", response.Payload.(o.Opaque).Type, len(response.Payload.(o.Opaque).Payload)))
			}
		}

		// TODO Dynamically determine what encoding method the agent is using and apply it
		// Encode return message into a gob
		messageBytes := new(bytes.Buffer)
		err = gob.NewEncoder(messageBytes).Encode(response)
		if err != nil {
			err = fmt.Errorf("there was an error gob encoding the return message: %s", err)
			return false
		}

		// TODO Dynamically determine what encryption method the agent is using and apply it

		var secret []byte
		if agents.Agents[linkedAgent].Authenticated {
			// The OPAQUE key is 64 bytes long but AES can only use a 32-byte key
			if len(agents.Agents[linkedAgent].Secret) > 32 {
				k := sha256.Sum256(agents.Agents[linkedAgent].Secret)
				secret = k[:]
			} else {
				secret = agents.Agents[linkedAgent].Secret
			}
		} else {
			k := sha256.Sum256([]byte("merlin"))
			secret = k[:]
		}

		var encryptedBytes []byte
		encryptedBytes, err = util.AESEncrypt(messageBytes.Bytes(), secret)
		if err != nil {
			return false
		}

		delegate := messages.Delegate{
			ID:      linkedAgent,
			Payload: encryptedBytes,
		}
		delegates = append(delegates, delegate)
		return true
	})
	return
}

// delegatesIn processes incoming messages for linked agents that are in the Delegates field of a Base message
func delegatesIn(id uuid.UUID, delegates []messages.Delegate) {
	for _, delegate := range delegates {
		var secret []byte

		// TODO DO NOT USE THIS HARD CODED PSK

		// See if the agent has previously successfully registered
		agent, ok := agents.Agents[delegate.ID]
		if ok {
			// The OPAQUE key is 64 bytes long but AES can only use a 32-byte key
			if len(agent.Secret) > 0 {
				k := sha256.Sum256(agent.Secret)
				secret = k[:]
			}
		} else {
			// The linked agent's Base message agent ID is the same as a listeners ID until it authenticates
			listener, err := lrepo.GetListenerByID(delegate.ID)
			if err != nil {
				logging.Message("warn", fmt.Sprintf("there was an error getting the listener for delegate message with an ID of %s: %s", delegate.ID, err))
				break
			}
			options := listener.GetConfiguredOptions()
			if options["psk"] != "" {
				k := sha256.Sum256([]byte(options["psk"]))
				secret = k[:]
			} else {
				logging.Message("warn", fmt.Sprintf("Unable to find PSK for listener %s", listener.ID))
				break
			}
		}

		// Decrypt message
		decryptedBytes, err := util.AESDecrypt(delegate.Payload, secret)
		if err != nil {
			logging.Message("warn", err.Error())
			break
		}

		// Gob decode
		var msg messages.Base
		reader := bytes.NewReader(decryptedBytes)
		err = gob.NewDecoder(reader).Decode(&msg)
		if err != nil {
			logging.Message("warn", fmt.Sprintf("there was an error decoding the delegate message payload for %s: %s", delegate.ID, err))
			break
		}

		// Add the link agent to a list on the associated parent agent
		//agents.Agents[id].LinkedAgents = append(agents.Agents[id].LinkedAgents, msg.ID)
		agents.Agents[id].LinkedAgents.Store(msg.ID, true)

		// Process the embedded Base message
		err = In(msg)
		if err != nil {
			logging.Message("warn", err.Error())
			break
		}
	}
}
