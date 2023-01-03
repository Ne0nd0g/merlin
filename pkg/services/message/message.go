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

// Package message is a service to process and return Agent Base messages
package message

import (
	// Standard
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	messageAPI "github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/delegate"
	delegateMemory "github.com/Ne0nd0g/merlin/pkg/delegate/memory"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/listeners"
	"github.com/Ne0nd0g/merlin/pkg/listeners/http"
	httpMemory "github.com/Ne0nd0g/merlin/pkg/listeners/http/memory"
	"github.com/Ne0nd0g/merlin/pkg/listeners/tcp"
	tcpMemory "github.com/Ne0nd0g/merlin/pkg/listeners/tcp/memory"
	"github.com/Ne0nd0g/merlin/pkg/listeners/udp"
	udpMemory "github.com/Ne0nd0g/merlin/pkg/listeners/udp/memory"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/pkg/services/job"
)

// Service is a structure with methods that execute the service functions for Agent messages
type Service struct {
	agentService *agent.Service
	jobService   *job.Service
	listener     listeners.Listener
	delegates    delegate.Repository
}

// NewMessageService is a factory to create and return a ListenerService
func NewMessageService(id uuid.UUID) (*Service, error) {
	l, err := listener(id)
	if err != nil {
		return nil, fmt.Errorf("pkg/service/message.NewMessageService(): %s", err)
	}
	lhs := &Service{
		listener:     l,
		agentService: agent.NewAgentService(),
		jobService:   job.NewJobService(),
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
	if err == nil {
		return &tcpListener, err
	}
	// Check the UDP Listener's Repository
	udpRepo := withUDPMemoryListenerRepository()
	udpListener, err := udpRepo.ListenerByID(id)
	if err == nil {
		return &udpListener, err
	}
	return nil, fmt.Errorf("pkg/services/message.listener(): %s", err)
}

// withHTTPMemoryListenerRepository retrieves an in-memory HTTP Listener repository interface used to manage Listener object
func withHTTPMemoryListenerRepository() http.Repository {
	return httpMemory.NewRepository()
}

// withTCPMemoryListenerRepository retrieves an in-memory TCP Listener repository interface used to manage Listener object
func withTCPMemoryListenerRepository() tcp.Repository {
	return tcpMemory.NewRepository()
}

// withUDPMemoryListenerRepository retrieves an in-memory UDP Listener repository interface used to manage Listener object
func withUDPMemoryListenerRepository() udp.Repository {
	return udpMemory.NewRepository()
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
func (s *Service) Handle(id uuid.UUID, data []byte) (rdata []byte, err error) {
	if core.Debug {
		logging.Message("debug", fmt.Sprintf("pkg/service/message.Handle(): entering into function with ID: %s, Data length %d", id, len(data)))
	}
	//fmt.Printf("pkg/service/message.Handle(): entering into function with ID: %s, Data length %d\n", id, len(data))

	agent, err := s.agentService.Agent(id)
	if err != nil {
		if core.Debug {
			logging.Message("debug", fmt.Sprintf("pkg/service/message.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
		}
	}

	// If the agent exists then get its encryption key
	// If the agent does not exist, leve th key blank and then the listener's key will be used
	var key []byte
	if err == nil {
		key = agent.Secret()
	}

	msg, err := s.listener.Deconstruct(data, key)
	if err != nil {
		return nil, err
	}

	var returnMessage messages.Base
	// Agent authentication
	if !s.agentService.Authenticated(msg.ID) {
		returnMessage, err = s.listener.Authenticate(msg.ID, msg.Payload)
		if err != nil {
			return nil, err
		}
		// The Authentication process does not return jobs
		// Unauthenticated messages use the interface PSK, not the agent PSK
		// the agent could be authenticated after processing the message
		if s.agentService.Authenticated(msg.ID) {
			// It doesn't matter if an error is returned because we'll send in an empty key and the listener's key will be used
			agent, err = s.agentService.Agent(id)
			if err != nil {
				if core.Debug {
					logging.Message("debug", fmt.Sprintf("pkg/service/message.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
				}
			} else {
				key = agent.Secret()
			}
		}
		return s.listener.Construct(returnMessage, key)
	}

	// Validate the agent exists
	// Needs to be here because delegate messages come into Handle without an id
	if !s.agentService.Exist(msg.ID) {
		// Create a new agent
		a, err := agents.NewAgent(id, []byte(s.listener.PSK()), nil, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		// Add agent to repository
		err = s.agentService.Add(a)
		if err != nil {
			return nil, err
		}
	}

	// Update the Agent's status checkin time
	err = s.agentService.UpdateStatusCheckin(agent.ID(), time.Now().UTC())
	if err != nil {
		messageAPI.ErrorMessage(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
	}

	// Handle incoming message type
	switch msg.Type {
	case messages.CHECKIN:
		// Nothing to do
	case messages.JOBS:
		err = s.jobService.Handler(msg.Payload.([]jobs.Job))
		if err != nil {
			messageAPI.ErrorMessage(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
			return
		}
	default:
		err = fmt.Errorf("unhandled authenticated messages.Base type %s", messages.String(msg.Type))
		messageAPI.ErrorMessage(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
		return
	}

	// Send delegates to associated handler
	if len(msg.Delegates) > 0 {
		err = s.delegate(id, msg.Delegates)
		if err != nil {
			return
		}
	}

	// Get return jobs
	// TODO ensure jobs.Get doesn't return delegate or job
	returnJobs, err := s.jobService.Get(msg.ID)

	if len(returnJobs) > 0 {
		returnMessage.Type = messages.JOBS
		returnMessage.Payload = returnJobs
	} else {
		returnMessage.Type = messages.IDLE
	}

	returnMessage.ID = msg.ID

	// Get delegate messages
	returnMessage.Delegates, err = s.getDelegates(msg.ID)
	if err != nil {
		return nil, err
	}

	// Get a copy of the Agent structure, so we can later extract the padding size
	agent, err = s.agentService.Agent(msg.ID)
	if err != nil {
		return nil, err
	}

	// Add padding here since we already have an agent service to get the needed information
	returnMessage.Padding = core.RandStringBytesMaskImprSrc(agent.Padding())

	return s.listener.Construct(returnMessage, agent.Secret())
}

// delegate takes in a list of delegate messages from their associated parent agent and processes them according to their
// associated Listener configuration.
func (s *Service) delegate(parent uuid.UUID, delegates []messages.Delegate) error {
	//fmt.Printf("pkg/service/message.delegate(): entered into function with %d delegate messages\n", len(delegates))
	for _, delegate := range delegates {
		//fmt.Printf("Delegate message for agent: %s and listener: %s\n", delegate.Agent, delegate.Listener)

		var lhService *Service
		var rdata []byte
		var err error
		// Get a new Listener Handler Service
		lhService, err = NewMessageService(delegate.Listener)
		if err != nil {
			if core.Verbose {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Warn,
					Time:    time.Now().UTC(),
					Error:   true,
					Message: fmt.Sprintf("pkg/services/message.delegate(): %s", err),
				})
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Info,
					Time:    time.Now().UTC(),
					Message: "Brute forcing all available listeners as a last resort to see if one of them can handle this message...",
				})
			}
			lhService, rdata, err = bruteForceListener(delegate.Agent, delegate.Payload)
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level: messageAPI.Warn,
					Time:  time.Now().UTC(),
					Error: true,
					Message: fmt.Sprintf("A delegate message was recieved from %s for the non-existent listener %s.\n"+
						"Attempts to brute force all existing Listeners to find one configure to handle the message failed.\n"+
						"Create a listener that matches the Agent's configuration before it reaches the maximum failed of login\n "+
						"attempts, or try to re-link the agent, to recover control of it. %s", delegate.Agent, delegate.Listener, time.Now().UTC()),
				})
				break
			}
			if core.Verbose {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Success,
					Time:    time.Now().UTC(),
					Message: fmt.Sprintf("Brute force attempt was successful. Listener %s can handle messages from %s", lhService.listener.ID(), delegate.Agent),
				})
			}
		} else {
			// Send in the delegate message
			rdata, err = lhService.Handle(delegate.Agent, delegate.Payload)
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Warn,
					Time:    time.Now().UTC(),
					Error:   true,
					Message: fmt.Sprintf("there was an error handling delegate message from %s: %s\n", delegate.Agent, err),
				})
				break
			}
		}

		// Add the parent/child link if it doesn't already exist
		linked, err := s.agentService.Linked(parent, delegate.Agent)
		if err != nil {
			return err
		}
		if !linked {
			//fmt.Printf("Adding child link %s to parent %s\n", delegate.Agent, parent)
			err = s.agentService.Link(parent, delegate.Agent)
			if err != nil {
				return err
			}
		}

		if s.agentService.Authenticated(delegate.Agent) {
			// Set the child Agent's listener
			err = s.agentService.UpdateListener(delegate.Agent, delegate.Listener)
			if err != nil {
				return fmt.Errorf("pkg/services/message.delegate(): there was an error updating the delegate Agent's Listener ID: %s", err)
			}
		}

		// Add encrypted/encoded return message Base structure (bytes) to the repository
		//fmt.Printf("Storing return delegate message bytes(%d) for %s\n", len(rdata), delegate.Agent)
		s.delegates.Add(delegate.Agent, rdata)
	}
	return nil
}

// getDelegates retrieves messages stored in the delegates repository for the passed in Agent ID
func (s *Service) getDelegates(id uuid.UUID) ([]messages.Delegate, error) {
	// fmt.Printf("Getting delegate messages for %s\n", id)
	var delegates []messages.Delegate

	// Unauthenticated agents shouldn't message delegates
	if !s.agentService.Authenticated(id) {
		//fmt.Printf("%s is not an authenticated agent, returning empty\n", id)
		return delegates, nil
	}

	links, err := s.agentService.Links(id)
	if err != nil {
		return delegates, err
	}

	if len(links) > 0 {
		for _, link := range links {
			datas := s.delegates.Get(link)
			for _, data := range datas {
				d := messages.Delegate{
					Agent:   link,
					Payload: data,
				}
				// Recursive Get
				d.Delegates, err = s.getDelegates(link)
				if err != nil {
					return delegates, err
				}
				delegates = append(delegates, d)
			}
		}
	}
	return delegates, nil
}

func bruteForceListener(id uuid.UUID, payload []byte) (lhService *Service, rdata []byte, err error) {
	// Check the TCP Listener's Repository
	tcpRepo := withTCPMemoryListenerRepository()
	tcpListeners := tcpRepo.Listeners()
	if len(tcpListeners) > 0 {
		for _, listener := range tcpListeners {
			lhService, err = NewMessageService(listener.ID())
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Warn,
					Time:    time.Now().UTC(),
					Error:   true,
					Message: fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err),
				})
				break
			}
			rdata, err = lhService.Handle(id, payload)
			if err == nil {
				// Found a listener that didn't error out handling message
				return
			}
		}
	}

	// Check the UDP Listener's Repository
	udpRepo := withUDPMemoryListenerRepository()
	udpListeners := udpRepo.Listeners()
	if len(udpListeners) > 0 {
		for _, listener := range udpListeners {
			lhService, err = NewMessageService(listener.ID())
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Warn,
					Time:    time.Now().UTC(),
					Error:   true,
					Message: fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err),
				})
				break
			}
			rdata, err = lhService.Handle(id, payload)
			if err == nil {
				// Found a listener that didn't error out handling message
				return
			}
		}
	}

	// Check the HTTP Listener's Repository
	httpRepo := withHTTPMemoryListenerRepository()
	httpListeners := httpRepo.Listeners()
	if len(httpListeners) > 0 {
		for _, listener := range httpListeners {
			lhService, err = NewMessageService(listener.ID())
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Warn,
					Time:    time.Now().UTC(),
					Error:   true,
					Message: fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err),
				})
				break
			}
			rdata, err = lhService.Handle(id, payload)
			if err == nil {
				// Found a listener that didn't error out handling message
				return
			}
		}
	}
	err = fmt.Errorf("pkg/services/message.bruteForceListener(): listener brute force unsuccessful")
	return
}
