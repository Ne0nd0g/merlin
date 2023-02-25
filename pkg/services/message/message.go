// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2023  Russel Van Tuyl

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
	"github.com/Ne0nd0g/merlin/pkg/listeners/smb"
	smbMemory "github.com/Ne0nd0g/merlin/pkg/listeners/smb/memory"
	"math/rand"
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
	// Check the SMB Listener's Repository
	smbRepo := withSMBMemoryListenerRepository()
	smbListener, err := smbRepo.ListenerByID(id)
	if err == nil {
		return &smbListener, err
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

// withSMBMemoryListenerRepository retrieves an in-memory SMB Listener repository interface used to manage Listener object
func withSMBMemoryListenerRepository() smb.Repository {
	return smbMemory.NewRepository()
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
	// If the agent does not exist, leave the key blank and then the listener's key will be used
	var key []byte
	if err == nil {
		key = agent.Secret()
	}

	// If the Agent exists, and it's Listener ID is empty, set it
	if err == nil {
		if agent.Listener() == uuid.Nil {
			err = s.agentService.UpdateListener(id, s.listener.ID())
			if err != nil {
				err = fmt.Errorf("pkg/service/message.Handle(): %s", err)
				return
			}
		}
	}

	msg, err := s.listener.Deconstruct(data, key)
	if err != nil {
		logging.Message("debug", fmt.Sprintf("pkg/services/message.Handle(): there was an error deconstructing the message for agent %s: %s", id, err))
		// Unable to deconstruct because this listener's transforms don't match what the Agent used
		messageAPI.SendBroadcastMessage(messageAPI.ErrorMessage(fmt.Sprintf("Ensure listener %s is configured the exact same way as the agent. If not create a new listener with the correct configuration and try again.", s.listener.ID())))
		// If there is an orphaned agent, we can try to send back a message to re-accomplish authentication
		// Unable to deconstruct because the message wasn't encrypted with the PSK; likely encrypted with the Agent's session key established during authentication
		messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
			Level:   messageAPI.Note,
			Time:    time.Now().UTC(),
			Error:   false,
			Message: fmt.Sprintf("Orphaned agent request from %s detected, instructing agent to re-authenticate", id),
		})
		msg.ID = id
	}

	var returnMessage messages.Base
	// Agent authentication
	if !s.agentService.Authenticated(msg.ID) {
		returnMessage, err = s.listener.Authenticate(msg.ID, msg.Payload)
		if err != nil {
			return nil, err
		}
		returnMessage.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(4096))
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

	return s.getBase(id)
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
		var bruteforced bool

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
			}
			messageAPI.SendBroadcastMessage(messageAPI.ErrorMessage(fmt.Sprintf("A delegate message was received from %s for the non-existent listener %s.", delegate.Agent, delegate.Listener)))
			messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
				Level:   messageAPI.Info,
				Time:    time.Now().UTC(),
				Message: "Brute forcing all available listeners as a last resort to see if one of them can handle this message...",
			})
			lhService, rdata, err = bruteForceListener(delegate.Agent, delegate.Payload)
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level: messageAPI.Warn,
					Time:  time.Now().UTC(),
					Error: true,
					Message: fmt.Sprintf("A delegate message was received from %s for the non-existent listener %s.\n"+
						"Attempts to brute force all existing Listeners to find one configure to handle the message failed.\n"+
						"Create a listener that matches the Agent's configuration before it reaches the maximum failed of login\n "+
						"attempts, or try to re-link the agent, to recover control of it. %s", delegate.Agent, delegate.Listener, time.Now().UTC()),
				})
				break
			}
			bruteforced = true
			if s.agentService.Authenticated(delegate.Agent) {
				err = s.agentService.UpdateListener(delegate.Agent, lhService.listener.ID())
				if err != nil {
					return fmt.Errorf("pkg/services/message.delegate(): %s", err)
				}
			}
			messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
				Level:   messageAPI.Success,
				Time:    time.Now().UTC(),
				Message: fmt.Sprintf("Brute force attempt was successful. Listener %s can handle messages from Agent %s. Instructing Agent to use this Listener ID", lhService.listener.ID(), delegate.Agent),
			})

			// Add an Agent Control job for the Agent to change it's associated listener
			var job string
			job, err = s.jobService.Add(delegate.Agent, "changelistener", []string{"listener", lhService.listener.ID().String()})
			if err != nil {
				messageAPI.SendBroadcastMessage(messageAPI.ErrorMessage(err.Error()))
			} else {
				messageAPI.SendBroadcastMessage(messageAPI.UserMessage{
					Level:   messageAPI.Note,
					Time:    time.Now().UTC(),
					Message: fmt.Sprintf("%s", job),
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
			// If the listener had to be bruteforced, then the Agent's listener has already been updated
			if !bruteforced {
				err = s.agentService.UpdateListener(delegate.Agent, delegate.Listener)
				if err != nil {
					return fmt.Errorf("pkg/services/message.delegate(): there was an error updating the delegate Agent's Listener ID: %s", err)
				}
			}
		}

		// Add encrypted/encoded return message Base structure (bytes) to the repository
		//fmt.Printf("Storing return delegate message bytes(%d) for %s\n", len(rdata), delegate.Agent)
		if len(rdata) > 0 {
			s.delegates.Add(delegate.Agent, rdata)
		}
	}
	return nil
}

// getBase builds a return Base message for the Agent id, encodes/encrypts it, and returns it as bytes.
// If there are any Jobs, they will be added to the Base message here
func (s *Service) getBase(id uuid.UUID) (data []byte, err error) {
	//fmt.Printf("Getting Base messages for %s\n", id)
	// Ensure the id is for a valid Agent
	var agent agents.Agent
	agent, err = s.agentService.Agent(id)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.getBase(): %s", err)
		return
	}

	returnMessage := messages.Base{
		Version:   0,
		ID:        id,
		Type:      messages.IDLE,
		Payload:   nil,
		Padding:   "",
		Token:     "",
		Delegates: nil,
	}

	var returnJobs []jobs.Job
	// Get return jobs
	returnJobs, err = s.jobService.Get(id)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.getBase(): %s", err)
		return
	}

	if len(returnJobs) > 0 {
		returnMessage.Type = messages.JOBS
		returnMessage.Payload = returnJobs
	}

	// Get delegate messages
	returnMessage.Delegates, err = s.getDelegates(id)
	if err != nil {
		// Do not return an error because it will cause the Parent Agent to quit functioning
		messageAPI.SendBroadcastMessage(messageAPI.ErrorMessage(fmt.Sprintf("pkg/services/message.getBase(): %s", err)))
	}

	// Add padding here since we already have an agent service to get the needed information
	padding := agent.Padding()

	if padding > 0 {
		padding = rand.Intn(padding)
	} else if agent.Comms() == (agents.Comms{}) {
		// If we don't know what the Agent's padding configuration is, use this default number
		padding = rand.Intn(4096)
	}
	returnMessage.Padding = core.RandStringBytesMaskImprSrc(padding)

	// Synchronous Agents that have nothing to say should not return an IDLE message
	if (agent.Comms().Proto == "tcp-bind" || agent.Comms().Proto == "tcp-reverse" || agent.Comms().Proto == "udp-bind" || agent.Comms().Proto == "udp-reverse" || agent.Comms().Proto == "smb-bind" || agent.Comms().Proto == "smb-reverse") && returnMessage.Type == messages.IDLE && len(returnMessage.Delegates) <= 0 {
		return nil, nil
	}
	//fmt.Printf("Agent: %s, Comms: %s, Message Type: %d, Delegates: %d\n", agent.ID(), agent.Comms().Proto, returnMessage.Type, len(returnMessage.Delegates))

	// If the Listener associated with this Message Handler doesn't belong to the Agent, then get the one that is and use it
	if agent.Listener() != s.listener.ID() {
		var l listeners.Listener
		l, err = listener(agent.Listener())
		if err != nil {
			err = fmt.Errorf("pkg/services/message.getBase() for Agent %s: %s", agent.ID(), err)
			return
		}
		return l.Construct(returnMessage, agent.Secret())
	}
	return s.listener.Construct(returnMessage, agent.Secret())
}

// getDelegates retrieves messages stored in the delegates repository for the passed in Agent ID
func (s *Service) getDelegates(id uuid.UUID) ([]messages.Delegate, error) {
	//fmt.Printf("Getting delegate messages for %s\n", id)
	var delegates []messages.Delegate

	// Unauthenticated agents shouldn't message delegates
	if !s.agentService.Authenticated(id) {
		//fmt.Printf("%s is not an authenticated agent, returning empty\n", id)
		return delegates, nil
	}

	// Get a list of child Agents
	links, err := s.agentService.Links(id)
	if err != nil {
		return delegates, err
	}

	// If there are any child Agents, get return messages
	if len(links) > 0 {
		// For each child Agent
		for _, link := range links {
			// Get messages from the Delegate repository
			delegateMessages := s.delegates.Get(link)
			// If any delegate messages were returned, add them to the list of return delegates
			if len(delegateMessages) > 0 {
				for _, msg := range delegateMessages {
					d := messages.Delegate{
						Agent:   link,
						Payload: msg,
					}
					// Recursive Get
					d.Delegates, err = s.getDelegates(link)
					if err != nil {
						return delegates, err
					}
					delegates = append(delegates, d)
				}
			}
			if s.agentService.Authenticated(link) {
				// See if there are any Base messages (likely Jobs) for the delegate
				var rdata []byte
				rdata, err = s.getBase(link)
				if err != nil {
					err = fmt.Errorf("pkg/services/message/getDelegate(): %s", err)
					return delegates, err
				}
				// If there is an error, continue on. Happen when an Agent isn't authenticated and getBase can't find the Agent
				if len(rdata) > 0 {
					// Build the Delegate message
					d := messages.Delegate{
						Agent:   link,
						Payload: rdata,
					}
					delegates = append(delegates, d)
				}
			}
		}
	}
	return delegates, nil
}

// bruteForceListener iterates through all available listeners and tries to use it to decode/decrypt the message.
// Used as a recovery mechanism when the Server receives messages it doesn't have a Listener for to ensure Agents aren't lost
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

	// Check the SMB Listener's Repository
	smbRepo := withSMBMemoryListenerRepository()
	smbListeners := smbRepo.Listeners()
	if len(smbListeners) > 0 {
		for _, listener := range smbListeners {
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
