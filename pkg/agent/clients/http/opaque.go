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

package http

import (
	// Standard
	"crypto/sha256"
	"fmt"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// opaqueAuth is the top-level function that subsequently runs OPAQUE registration and authentication
func (client *Client) opaqueAuth(register bool) (messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.http.opaqueAuth()...")

	// Set, or reset, the secret used for JWT & JWE encryption key from PSK
	k := sha256.Sum256([]byte(client.psk))
	client.secret = k[:]

	// OPAQUE Registration
	if register { // If the client has previously registered, then this will not be empty
		// Reset the OPAQUE User structure for when the Agent previously successfully authenticated
		// but the Agent needs to re-register with a new server
		if client.opaque != nil {
			if client.opaque.Kex != nil { // Only exists after successful authentication which occurs after registration
				client.opaque = nil
			}
		}
		// OPAQUE Registration steps
		err := client.opaqueRegister()
		if err != nil {
			return messages.Base{}, fmt.Errorf("there was an error performing OPAQUE User Registration:\r\n%s", err)
		}
	}

	// OPAQUE Authentication steps
	msg, err := client.opaqueAuthenticate()
	if err != nil {
		return msg, fmt.Errorf("there was an error performing OPAQUE User Authentication:\r\n%s", err)
	}

	// The OPAQUE derived Diffie-Hellman secret
	client.secret = []byte(client.opaque.Kex.SharedSecret.String())

	return msg, nil
}

//opaqueRegister is the logic used to perform the OPAQUE protocol Registration
func (client *Client) opaqueRegister() error {
	cli.Message(cli.DEBUG, "Entering into agent.opaqueRegister")
	cli.Message(cli.NOTE, "Starting OPAQUE Registration")

	msg := messages.Base{
		Type: messages.OPAQUE,
	}

	// Set the Agent's JWT to be self-generated
	var err error
	client.JWT, err = client.getJWT()
	if err != nil {
		return err
	}

	if client.opaque == nil {
		// Build OPAQUE RegInit message
		msg.Payload, client.opaque, err = opaque.UserRegisterInit(client.AgentID)
		if err != nil {
			return fmt.Errorf("there was an error creating the OPAQUE User Registration Initialization message:\r\n%s", err)
		}
		// Send OPAQUE RegInit message to the server
		cli.Message(cli.DEBUG, "Sending OPAQUE RegInit message")
		msg, err = client.SendMerlinMessage(msg)
		if err != nil {
			client.opaque = nil
			return fmt.Errorf("there was an error sending the OPAQUE User Registration Initialization message to the server:\r\n%s", err)
		}
		// Verify the message is for this agent
		if msg.ID != client.AgentID {
			return fmt.Errorf("message ID %s does not match agent ID %s", msg.ID, client.AgentID)
		}
		// Verify the payload type is correct
		if msg.Type != messages.OPAQUE {
			return fmt.Errorf("expected message type %s, recieved type %s", messages.String(messages.OPAQUE), messages.String(msg.Type))
		}
	} else {
		msg.Payload = opaque.Opaque{
			Type: opaque.RegInit,
		}
	}

	// Build OPAQUE RegComplete message
	msg.Payload, err = opaque.UserRegisterComplete(msg.Payload.(opaque.Opaque), client.opaque)
	if err != nil {
		return fmt.Errorf("there was an error creating the OPAQUE User Registration Complete message:\r\n%s", err)
	}
	// Send OPAQUE RegComplete to the server
	cli.Message(cli.DEBUG, "Sending OPAQUE RegComplete message")
	msg, err = client.SendMerlinMessage(msg)
	if err != nil {
		return fmt.Errorf("there was an error sending the OPAQUE User Registration Complete message to the server:\r\n%s", err)
	}
	// Verify the message is for this agent
	if msg.ID != client.AgentID {
		return fmt.Errorf("message ID %s does not match agent ID %s", msg.ID, client.AgentID)
	}
	// Verify the payload type is correct
	if msg.Type != messages.OPAQUE {
		return fmt.Errorf("expected message type %s, recieved type %s", messages.String(messages.OPAQUE), messages.String(msg.Type))
	}
	// Verify OPAQUE response is correct
	if msg.Payload.(opaque.Opaque).Type != opaque.RegComplete {
		return fmt.Errorf("expected OPAQUE message type %d, recieved type %d", opaque.RegComplete, msg.Payload.(opaque.Opaque).Type)
	}

	cli.Message(cli.NOTE, "OPAQUE registration complete")
	return nil
}

// opaqueAuthenticate is the logic used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) authentication
func (client *Client) opaqueAuthenticate() (messages.Base, error) {
	cli.Message(cli.NOTE, "Starting OPAQUE Authentication")

	msg := messages.Base{
		Type: messages.OPAQUE,
	}
	// Set the Agent's JWT to be self-generated
	var err error
	client.JWT, err = client.getJWT()
	if err != nil {
		return msg, err
	}

	// Build AuthInit message
	payload, err := opaque.UserAuthenticateInit(client.AgentID, client.opaque)
	if err != nil {
		return msg, fmt.Errorf("there was an error building the OPAQUE Authentication Initialization message:\r\n%s", err)
	}
	msg.Payload = payload
	// Send OPAQUE AuthInit message to the server
	cli.Message(cli.DEBUG, "Sending OPAQUE AuthInit message")
	msg, err = client.SendMerlinMessage(msg)
	if err != nil {
		return msg, fmt.Errorf("there was an error sending the OPAQUE User Authentication Initialization message to the server:\r\n%s", err)
	}
	// Verify the message is for this agent
	if msg.ID != client.AgentID {
		return msg, fmt.Errorf("message ID %s does not match agent ID %s", msg.ID, client.AgentID)
	}
	// Verify the payload type is correct
	if msg.Type != messages.OPAQUE {
		return msg, fmt.Errorf("expected message type %s, recieved type %s", messages.String(messages.OPAQUE), messages.String(msg.Type))
	}
	// When the Merlin server has restarted but doesn't know the agent
	if msg.Payload.(opaque.Opaque).Type == opaque.ReRegister {
		cli.Message(cli.NOTE, "Received OPAQUE ReRegister response, setting initial to false")
		return msg, nil
	}
	// Build AuthComplete message
	payload, err = opaque.UserAuthenticateComplete(msg.Payload.(opaque.Opaque), client.opaque)
	if err != nil {
		return msg, fmt.Errorf("there was an error creating the OPAQUE User Authentication Complete message:\r\n%s", err)
	}
	msg.Payload = payload
	// Save the OPAQUE derived Diffie-Hellman secret
	client.secret = []byte(client.opaque.Kex.SharedSecret.String())
	// Send OPAQUE AuthComplete to the server
	cli.Message(cli.DEBUG, "Sending OPAQUE AuthComplete message")
	msg, err = client.SendMerlinMessage(msg)
	if err != nil {
		return msg, fmt.Errorf("there was an error sending the OPAQUE User Authentication Complete message to the server:\r\n%s", err)
	}

	cli.Message(cli.SUCCESS, "Agent authentication successful")
	cli.Message(cli.DEBUG, "Leaving agent.opaqueAuthenticate without error")
	return msg, nil
}
