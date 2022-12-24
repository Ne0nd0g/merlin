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

// Package listener is a handler service to process and return Agent messages
package listener

import (
	// Standard
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/delegate"
	delegateMemory "github.com/Ne0nd0g/merlin/pkg/delegate/memory"
	"github.com/Ne0nd0g/merlin/pkg/listeners"
	"github.com/Ne0nd0g/merlin/pkg/listeners/http"
	httpMemory "github.com/Ne0nd0g/merlin/pkg/listeners/http/memory"
	"github.com/Ne0nd0g/merlin/pkg/listeners/tcp"
	tcpMemory "github.com/Ne0nd0g/merlin/pkg/listeners/tcp/memory"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/server/jobs"
	"github.com/Ne0nd0g/merlin/pkg/services/agent"
)

// HandlerService is a structure with methods that execute the service functions for Agent messages
type HandlerService struct {
	agentService *agent.Service
	listener     listeners.Listener
	delegates    delegate.Repository
}

// NewListenerHandlerService is a factory to create and return a ListenerService
func NewListenerHandlerService(id uuid.UUID) (*HandlerService, error) {
	l, err := listener(id)
	if err != nil {
		return nil, fmt.Errorf("pkg/services/handle/listener.NewHandlerService(): %s", err)
	}
	lhs := &HandlerService{
		listener:     l,
		agentService: agent.NewAgentService(),
		delegates:    withDelegateMemoryRepository(),
	}
	return lhs, nil
}

// listener checks all Listener repositories to find the Listener object and return it
func listener(id uuid.UUID) (listeners.Listener, error) {
	// Check the HTTP Listener's Repository
	httpRepo := withHTTPMemoryListenerRepository()
	httpListener, err := httpRepo.ListenerByID(id)
	if err == nil {
		return &httpListener, nil
	}
	// Check the TCP Listener's Repository
	tcpRepo := withTCPMemoryListenerRepository()
	tcpListener, err := tcpRepo.ListenerByID(id)
	return &tcpListener, err
}

// withHTTPMemoryListenerRepository retrieves an in-memory HTTP Listener repository interface used to manage Listener object
func withHTTPMemoryListenerRepository() http.Repository {
	return httpMemory.NewRepository()
}

// withTCPMemoryListenerRepository retrieves an in-memory TCP Listener repository interface used to manage Listener object
func withTCPMemoryListenerRepository() tcp.Repository {
	return tcpMemory.NewRepository()
}

// withDelegateMemoryRepository retrieves an in-memory delegate message repository interface used to store/retrieve
// transformed peer-to-peer Agent messages
func withDelegateMemoryRepository() delegate.Repository {
	return delegateMemory.NewRepository()
}

// Handle is the primary entry function that processes incoming raw data Agent traffic.
// The raw data is decoded/decrypted by either Listener or Agent's secret key depending on if the Agent completed authentication.
// Delegate messages are handled here. Once completed, this function checks for return messages that belong to the input
// Agent and returns them along with any delegate messages.
func (lhs *HandlerService) Handle(id uuid.UUID, data []byte) (rdata []byte, err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("pkg/services/handle/listener.Handle(): entering into function with ID: %s, Data length %d", id, len(data)))
	}
	//fmt.Printf("pkg/services/handle/listener.Handle(): entering into function with ID: %s, Data length %d\n", id, len(data))

	agent, err := lhs.agentService.Agent(id)
	if err != nil {
		if core.Debug {
			logging.Message("debug", fmt.Sprintf("pkg/services/handle/listener.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
		}
	}

	// If the agent exists then get its encryption key
	// If the agent does not exist, leve th key blank and then the listener's key will be used
	var key []byte
	if err == nil {
		key = agent.Secret()
	}

	msg, err := lhs.listener.Deconstruct(data, key)
	if err != nil {
		return nil, err
	}

	var returnMessage messages.Base
	// Agent authentication
	if !lhs.agentService.Authenticated(msg.ID) {
		returnMessage, err = lhs.listener.Authenticate(msg.ID, msg.Payload)
		if err != nil {
			return nil, err
		}
		// The Authentication process does not return jobs
		// Unauthenticated messages use the interface PSK, not the agent PSK
		// the agent could be authenticated after processing the message
		if lhs.agentService.Authenticated(msg.ID) {
			// It doesn't matter if an error is returned because we'll send in an empty key and the listener's key will be used
			agent, err = lhs.agentService.Agent(id)
			if err != nil {
				if core.Debug {
					logging.Message("debug", fmt.Sprintf("pkg/services/handle/listener.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
				}
			} else {
				key = agent.Secret()
			}
		}
		return lhs.listener.Construct(returnMessage, key)
	}

	// Validate the agent exists
	// Needs to be here because delegate messages come into Handle without an id
	if !lhs.agentService.Exist(msg.ID) {
		// Create a new agent
		a, err := agents.NewAgent(id, []byte(lhs.listener.PSK()), nil, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		// Add agent to repository
		err = lhs.agentService.Add(a)
		if err != nil {
			return nil, err
		}
	}

	// Update the Agent's status checkin time
	err = lhs.agentService.UpdateStatusCheckin(agent.ID(), time.Now().UTC())

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

	// Send delegates to associated handler
	if len(msg.Delegates) > 0 {
		err = lhs.delegate(id, msg.Delegates)
		if err != nil {
			return
		}
	}

	// Get return jobs
	// TODO ensure jobs.Get doesn't return delegate or job
	returnJobs, err := jobs.Get(msg.ID)
	if len(returnJobs) > 0 {
		returnMessage.Type = messages.JOBS
		returnMessage.Payload = returnJobs
	} else {
		returnMessage.Type = messages.IDLE
	}

	returnMessage.ID = msg.ID

	// Get delegate messages
	returnMessage.Delegates, err = lhs.getDelegates(msg.ID)
	if err != nil {
		return nil, err
	}

	// Get a copy of the Agent structure so we can later extract the padding size
	agent, err = lhs.agentService.Agent(msg.ID)
	if err != nil {
		return nil, err
	}

	// Add padding here since we already have an agent service to get the needed information
	returnMessage.Padding = core.RandStringBytesMaskImprSrc(agent.Padding())

	return lhs.listener.Construct(returnMessage, agent.Secret())
}

// delegate takes in a list of delegate messages from their associated parent agent and processes them according to their
// associated Listener configuration.
func (lhs *HandlerService) delegate(parent uuid.UUID, delegates []messages.Delegate) error {
	//fmt.Printf("pkg/services/handle/listener.delegate(): entered into function with %d delegate messages\n", len(delegates))
	for _, delegate := range delegates {
		//fmt.Printf("Delegate message for agent: %s and listener: %s\n", delegate.Agent, delegate.Listener)

		// Get a new Listener Handler Service
		lhService, err := NewListenerHandlerService(delegate.Listener)
		if err != nil {
			fmt.Printf("there was an error getting a new listener handler service for %s: %s\n", delegate.Listener, err)
			break
		}

		// Send in the delegate message
		//fmt.Println("Calling listener service for delegate message...")
		rdata, err := lhService.Handle(delegate.Agent, delegate.Payload)
		if err != nil {
			fmt.Printf("there was an error handling delegate message from %s: %s\n", delegate.Agent, err)
			break
		}

		// Add the parent/child link if it doesn't already exist
		linked, err := lhs.agentService.Linked(parent, delegate.Agent)
		if err != nil {
			return err
		}
		if !linked {
			//fmt.Printf("Adding child link %s to parent %s\n", delegate.Agent, parent)
			err = lhs.agentService.Link(parent, delegate.Agent)
			if err != nil {
				return err
			}
		}

		// Add encrypted/encoded return message Base structure (bytes) to the repository
		//fmt.Printf("Storing return delegate message bytes(%d) for %s\n", len(rdata), delegate.Agent)
		lhs.delegates.Add(delegate.Agent, rdata)
	}
	return nil
}

// getDelegates retrieves messages stored in the delegates repository for the passed in Agent ID
func (lhs *HandlerService) getDelegates(id uuid.UUID) ([]messages.Delegate, error) {
	// fmt.Printf("Getting delegate messages for %s\n", id)
	var delegates []messages.Delegate

	// Unauthenticated agents shouldn't handle delegates
	if !lhs.agentService.Authenticated(id) {
		//fmt.Printf("%s is not an authenticated agent, returning empty\n", id)
		return delegates, nil
	}

	links, err := lhs.agentService.Links(id)
	if err != nil {
		return delegates, err
	}

	if len(links) > 0 {
		for _, link := range links {
			datas := lhs.delegates.Get(link)
			for _, data := range datas {
				d := messages.Delegate{
					Agent:   link,
					Payload: data,
				}
				// Recursive Get
				d.Delegates, err = lhs.getDelegates(link)
				if err != nil {
					return delegates, err
				}
				delegates = append(delegates, d)
			}
		}
	}
	//fmt.Printf("Returning %d delegate messages for %s without error\n", len(delegates), id)
	return delegates, nil
}
