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

// Package message is a service to process and return Agent Base messages
package message

import (
	// Standard
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message"
	messageMemory "github.com/Ne0nd0g/merlin/v2/pkg/client/message/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	"github.com/Ne0nd0g/merlin/v2/pkg/delegate"
	delegateMemory "github.com/Ne0nd0g/merlin/v2/pkg/delegate/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/http"
	httpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/http/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/smb"
	smbMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/smb/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/tcp"
	tcpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/tcp/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/udp"
	udpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/udp/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/job"
)

// Service is a structure with methods that execute the service functions for Agent messages
type Service struct {
	agentService  *agent.Service
	jobService    *job.Service
	listener      listeners.Listener
	delegates     delegate.Repository
	clientMsgRepo message.Repository
}

// NewMessageService is a factory to create and return a ListenerService
func NewMessageService(id uuid.UUID) (*Service, error) {
	l, err := listener(id)
	if err != nil {
		return nil, fmt.Errorf("pkg/service/message.NewMessageService(): %s", err)
	}
	lhs := &Service{
		listener:      l,
		agentService:  agent.NewAgentService(),
		jobService:    job.NewJobService(),
		delegates:     withDelegateMemoryRepository(),
		clientMsgRepo: withClientMessageMemoryRepository(),
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

func withClientMessageMemoryRepository() message.Repository {
	return messageMemory.NewRepository()
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

// Construct takes a Base message and executes the appropriate Listener's Transforms (encoding/encryption) on the input
// Base message and returns the Base message as bytes
func (s *Service) Construct(msg messages.Base) (data []byte, err error) {
	// Ensure the id is for a valid Agent
	var a agents.Agent
	a, err = s.agentService.Agent(msg.ID)
	if err != nil {
		err = fmt.Errorf("services/message.Construct(): %s", err)
		return
	}

	// Add padding here since we already have an agent service to get the needed information
	padding := a.Padding()

	if padding > 0 {
		padding = rand.Intn(padding) // #nosec G404 the random number is not used for secrets
	} else if a.Comms() == (agents.Comms{}) {
		// If we don't know what the Agent's padding configuration is, use this default number
		padding = rand.Intn(4096) // #nosec G404 the random number is not used for secrets
	}
	msg.Padding = core.RandStringBytesMaskImprSrc(padding)

	// If the Listener associated with this Message Handler doesn't belong to the Agent, then get the one that is and use it
	if a.Listener() != s.listener.ID() {
		var l listeners.Listener
		l, err = listener(a.Listener())
		if err != nil {
			err = fmt.Errorf("services/message.Construct() for Agent %s: %s", a.ID(), err)
			return
		}
		return l.Construct(msg, a.Secret())
	}
	return s.listener.Construct(msg, a.Secret())
}

// Handle is the primary entry function that processes incoming raw data Agent traffic.
// The raw data is decoded/decrypted by either Listener or Agent's secret key depending on if the Agent completed authentication.
// Delegate messages are handled here. Once completed, this function checks for return messages that belong to the input
// Agent and returns them along with any delegate messages.
func (s *Service) Handle(id uuid.UUID, data []byte) (rdata []byte, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "ID", id, "Data Length", len(data))
	defer slog.Log(context.Background(), logging.LevelTrace, "exiting from function", "Return Data Length", len(rdata), "error", err)
	//fmt.Printf("pkg/service/message.Handle(): entering into function with ID: %s, Data length %d\n", id, len(data))

	a, err := s.agentService.Agent(id)
	if err != nil {
		slog.Debug(fmt.Sprintf("pkg/service/message.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
	}

	// If the agent exists, then get its encryption key
	// If the agent does not exist, leave the key blank and then the listener's key will be used
	var key []byte
	if err == nil {
		key = a.Secret()
	}

	// If the Agent exists, and it's Listener ID is empty, set it
	if err == nil {
		//if agent.Listener() == uuid.Nil
		if a.Listener() != s.listener.ID() {
			err = s.agentService.UpdateListener(id, s.listener.ID())
			if err != nil {
				err = fmt.Errorf("pkg/service/message.Handle(): %s", err)
				return
			}
		}
	}

	var msg messages.Base
	if len(data) > 0 {
		msg, err = s.listener.Deconstruct(data, key)
		if err != nil {
			slog.Warn("there was an error deconstructing the message", "error", err, "agent", id)
			//logging.Message("debug", fmt.Sprintf("pkg/services/message.Handle(): there was an error deconstructing the message for agent %s: %s", id, err))
			// If there is an orphaned agent, we can try to send back a message to re-accomplish authentication
			// Unable to deconstruct because the message wasn't encrypted with the PSK; likely encrypted with the Agent's session key established during authentication
			slog.Warn(fmt.Sprintf("Orphaned agent request from %s detected, instructing agent to re-authenticate", id))
			s.clientMsgRepo.Add(message.NewMessage(message.Note, fmt.Sprintf("Orphaned agent request from %s detected, instructing agent to re-authenticate", id)))

			// Unable to deconstruct because this listener's transforms don't match what the Agent used
			s.clientMsgRepo.Add(message.NewMessage(message.Warn, fmt.Sprintf("Ensure listener %s is configured the exact same way as the agent. If not create a new listener with the correct configuration and try again.", s.listener.ID())))
			msg.ID = id
			// If the agent previously authenticated, connected to a different server, and then connected back to this one, it will need to re-authenticate
			if s.agentService.Exist(id) && s.agentService.Authenticated(id) {
				//fmt.Println("Orphaned, exists, and authenticated, resetting authentication")
				key = nil
				err = s.agentService.ResetAuthentication(id)
				if err != nil {
					s.clientMsgRepo.Add(message.NewErrorMessage(fmt.Errorf("there was an error resetting the authentication status for orphaned agent %s: %s", id, err)))
				}
			}
		}
	} else if !a.Authenticated() {
		msg.ID = id
		msg.Type = messages.CHECKIN
		s.clientMsgRepo.Add(message.NewMessage(message.Note, fmt.Sprintf("Orphaned peer-to-peer agent %s detected due an empty payload, instructing agent to re-authenticate", id)))
	}

	// The "link refresh" command causes the parent Agent to send back an empty Base message for the child
	// The parent can't construct a Base message for the child because it doesn't know the child Agent's configuration
	// If the server already knows about the child Agent, then it isn't orphaned and will not trigger the orphaned logic above
	if msg.ID == uuid.Nil {
		msg.ID = a.ID()
		if msg.Type == 0 {
			msg.Type = messages.CHECKIN
		}
	}

	var returnMessage messages.Base
	// Agent authentication
	if !s.agentService.Authenticated(msg.ID) {
		returnMessage, err = s.listener.Authenticate(msg.ID, msg.Payload)
		if err != nil {
			return nil, err
		}
		returnMessage.Padding = core.RandStringBytesMaskImprSrc(rand.Intn(4096)) // #nosec G404 the random number is not used for secrets
		// The Authentication process does not return jobs
		// Unauthenticated messages use the interface PSK, not the agent PSK
		// the agent could be authenticated after processing the message
		if s.agentService.Authenticated(msg.ID) {
			// It doesn't matter if an error is returned because we'll send in an empty key and the listener's key will be used
			a, err = s.agentService.Agent(id)
			if err != nil {
				slog.Debug(fmt.Sprintf("pkg/service/message.Handle(): there was an error getting the agent %s (this is OK): %s", id, err))
			} else {
				// Send a message to all connected CLI clients a new authenticated agent has connected
				m := message.NewMessage(message.Success, fmt.Sprintf("New authenticated Agent checkin for %s at %s", a.ID(), a.Initial().UTC().Format(time.RFC3339)))
				s.clientMsgRepo.Add(m)
				key = a.Secret()
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
	err = s.agentService.UpdateStatusCheckin(a.ID(), time.Now().UTC())
	if err != nil {
		slog.Error(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
	}

	// Handle the incoming message type
	switch msg.Type {
	case messages.CHECKIN:
		// Nothing to do
	case messages.JOBS:
		err = s.jobService.Handler(msg.Payload.([]jobs.Job))
		if err != nil {
			slog.Error(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
			return
		}
	default:
		err = fmt.Errorf("unhandled authenticated messages.Base type %s", msg.Type)
		slog.Error(fmt.Sprintf("pkg/service/message.Handle(): %s", err))
		return
	}

	// Send delegates to associated handler
	if len(msg.Delegates) > 0 {
		err = s.delegate(id, msg.Delegates)
		if err != nil {
			return
		}
	}

	// If the Base message being handled is for a peer-to-peer Agent, don't get a return Base message now
	// Return Base messages for peer-to-peer Agents are gathered when the parent Agent Base message is being handled
	if s.agentService.IsChild(id) {
		return nil, nil
	}
	return s.getBase(id)
}

// childDisconnect holds the business logic for the reset command that creates a final disconnect message for a child Agent
func (s *Service) childDisconnect(id uuid.UUID) (payload string, err error) {
	//fmt.Println("pkg/services/message.childDisconnect(): entering into function")

	// If child Agent is an upd-bind agent, tell it to reset the connection
	var a agents.Agent
	a, err = s.agentService.Agent(id)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.childDisconnect(): there was an error getting the child agent: %s", err)
		return
	}
	if a.Comms().Proto != "udp-bind" {
		// Only the UDP agent needs this notification. Other protocols like TCP can tell when the parent disconnects
		return
	}

	// Build the embedded Job telling the child to disconnect
	j := jobs.Job{
		AgentID: id,
		Type:    jobs.CONTROL,
		Payload: jobs.Command{Command: "reset"},
	}

	// Build the embedded Base message
	msg := messages.Base{
		ID:      id,
		Type:    messages.JOBS,
		Payload: []jobs.Job{j},
	}

	// Transform the Base message
	var data []byte
	data, err = s.Construct(msg)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.getBase(): there was an error constructing the embeded Base message for agent %s with the unlink job: %s", id, err)
		return
	}
	// Base64 encode the data
	payload = base64.StdEncoding.EncodeToString(data)

	return
}

// delegate takes in a list of delegate messages from their associated parent agent and processes them according to their
// associated Listener configuration.
func (s *Service) delegate(parent uuid.UUID, delegates []messages.Delegate) error {
	//fmt.Printf("pkg/service/message.delegate(): entered into function with %d delegate messages\n", len(delegates))
	for _, del := range delegates {
		//fmt.Printf("Delegate message for agent: %s and listener: %s\n", delegate.Agent, delegate.Listener)

		var lhService *Service
		var rdata []byte
		var err error
		var bruteforced bool

		// Get a new Listener Handler Service
		lhService, err = NewMessageService(del.Listener)
		if err != nil {
			if core.Verbose {
				slog.Error(fmt.Sprintf("pkg/services/message.delegate(): %s", err))
			}
			s.clientMsgRepo.Add(message.NewErrorMessage(fmt.Errorf("a delegate message was received from %s for the non-existent listener %s", del.Agent, del.Listener)))
			s.clientMsgRepo.Add(message.NewMessage(message.Info, "Brute forcing all available listeners as a last resort to see if one of them can handle this message..."))

			lhService, rdata, err = bruteForceListener(del.Agent, del.Payload)
			if err != nil {
				msg := fmt.Sprintf("A delegate message was received from %s for the non-existent listener %s.\n"+
					"Attempts to brute force all existing Listeners to find one configure to handle the message failed.\n"+
					"Create a listener that matches the Agent's configuration before it reaches the maximum failed of login\n "+
					"attempts, or try to re-link the agent, to recover control of it. %s", del.Agent, del.Listener, time.Now().UTC())
				s.clientMsgRepo.Add(message.NewMessage(message.Warn, msg))
				break
			}
			bruteforced = true
			if s.agentService.Authenticated(del.Agent) {
				err = s.agentService.UpdateListener(del.Agent, lhService.listener.ID())
				if err != nil {
					return fmt.Errorf("pkg/services/message.delegate(): %s", err)
				}
			}
			s.clientMsgRepo.Add(message.NewMessage(message.Success, fmt.Sprintf("Brute force attempt was successful. Listener %s can handle messages from Agent %s. Instructing Agent to use this Listener ID", lhService.listener.ID(), del.Agent)))

			// Add an Agent Control job for the Agent to change its associated listener
			var j string
			j, err = s.jobService.Add(del.Agent, "changelistener", []string{"listener", lhService.listener.ID().String()})
			if err != nil {
				s.clientMsgRepo.Add(message.NewErrorMessage(err))
			} else {
				s.clientMsgRepo.Add(message.NewMessage(message.Note, fmt.Sprintf("%s", j)))
			}
		} else {
			// Send in the delegate message
			rdata, err = lhService.Handle(del.Agent, del.Payload)
			if err != nil {
				slog.Error(fmt.Sprintf("there was an error handling delegate message from %s: %s\n", del.Agent, err))
				break
			}
		}

		// Add the parent/child link if it doesn't already exist
		linked, err := s.agentService.Linked(parent, del.Agent)
		if err != nil {
			return err
		}
		if !linked {
			//fmt.Printf("Adding child link %s to parent %s\n", delegate.Agent, parent)
			err = s.agentService.Link(parent, del.Agent)
			if err != nil {
				return err
			}
		}

		if s.agentService.Authenticated(del.Agent) {
			// Set the child Agent's listener
			// If the listener had to be bruteforced, then the Agent's listener has already been updated
			if !bruteforced {
				err = s.agentService.UpdateListener(del.Agent, del.Listener)
				if err != nil {
					return fmt.Errorf("pkg/services/message.delegate(): there was an error updating the delegate Agent's Listener ID: %s", err)
				}
			}
		}

		// Add encrypted/encoded return message Base structure (bytes) to the repository
		//fmt.Printf("Storing return delegate message bytes(%d) for %s\n", len(rdata), delegate.Agent)
		if len(rdata) > 0 {
			s.delegates.Add(del.Agent, rdata)
		}
	}
	//fmt.Printf("pkg/service/message.delegate(): returning nil\n")
	return nil
}

// getBase builds a return Base message for the Agent id, encodes/encrypts it, and returns it as bytes.
// If there are any Jobs, they will be added to the Base message here
func (s *Service) getBase(id uuid.UUID) (data []byte, err error) {
	//fmt.Printf("Getting Base messages for %s\n", id)
	// Ensure the id is for a valid Agent
	var a agents.Agent
	a, err = s.agentService.Agent(id)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.getBase(): %s", err)
		return
	}

	returnMessage := messages.Base{
		ID:        id,
		Type:      messages.IDLE,
		Payload:   nil,
		Padding:   "",
		Token:     "",
		Delegates: nil,
	}

	// Get return jobs
	var returnJobs []jobs.Job
	returnJobs, err = s.jobService.Get(id)
	if err != nil {
		err = fmt.Errorf("pkg/services/message.getBase(): %s", err)
		return
	}

	if len(returnJobs) > 0 {
		returnMessage.Type = messages.JOBS

		// Check for an unlink job
		for i, j := range returnJobs {
			// Check to see if it is an unlink job
			if j.Type == jobs.MODULE {
				cmd := j.Payload.(jobs.Command)
				if strings.ToLower(cmd.Command) == "unlink" {
					j.Payload, err = s.unlink(id, cmd)
					if err != nil {
						slog.Error(fmt.Sprintf("pkg/services/message.getBase(): %s", err))
						break
					}
					returnJobs[i] = j
				}
			}
		}
		returnMessage.Payload = returnJobs
	} else if a.Authenticated() && !a.Alive() {
		// If the Agent is authenticated, has no return jobs, and is not alive return nothing
		// Happens when child p2p agents are instructed to exit, but the server is still tracking the agent
		// The Agent will NOT be alive, but still needs to send the exit message
		return nil, nil
	}

	// Get delegate messages
	returnMessage.Delegates, err = s.getDelegates(id)
	if err != nil {
		// Do not return an error because it will cause the Parent Agent to quit functioning
		slog.Error(fmt.Sprintf("pkg/services/message.getBase(): %s", err))
	}

	// Muted Agents that have nothing to say should not return an IDLE message
	var sleep time.Duration
	sleep, err = time.ParseDuration(a.Comms().Wait)
	if err == nil && sleep < 0 && len(returnMessage.Delegates) <= 0 && len(returnJobs) <= 0 {
		return nil, nil
	}

	return s.Construct(returnMessage)
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
				slog.Error(fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err))
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
				slog.Error(fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err))
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
				slog.Error(fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err))
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
				slog.Error(fmt.Sprintf("pkg/services/message.bruteForceListener(): %s", err))
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

// unlink holds the business logic for the unlink command that creates a final disconnect message for the child and adds
// it as an argument to the parent's unlink message
// Tried to do this in other packages, but it created circular dependencies
func (s *Service) unlink(parentID uuid.UUID, cmd jobs.Command) (returnCmd jobs.Command, err error) {
	if len(cmd.Args) > 0 {
		cmd.Args = []string{cmd.Args[0], ""}
		// Convert UUID from string
		var childID uuid.UUID
		childID, err = uuid.Parse(cmd.Args[0])
		if err != nil {
			err = fmt.Errorf("pkg/services/message.unlink(): there was an error converting the child agent's UUID: %s from a string for the unlink command: %s", cmd.Args[0], err)
			return
		}
		// Get the child agent's disconnect job and add it as an argument to the parent's unlink job
		cmd.Args[1], err = s.childDisconnect(childID)
		if err != nil {
			err = fmt.Errorf("pkg/services/message.unlink(): there was an error getting the child agent's disconnect job: %s", err)
			return
		}
		// If the child agent's disconnect job is empty, then just send the parent agent's unlink job
		if cmd.Args[1] == "" {
			cmd.Args = []string{cmd.Args[0]}
		}
		returnCmd = cmd

		// Ensure the child agent is unlinked
		err = s.agentService.Unlink(parentID, childID)
		if err != nil {
			err = fmt.Errorf("pkg/services/message.unlink(): %s", err)
			return
		}
	} else {
		err = fmt.Errorf("pkg/services/message.unlink(): unlink job for %s did not contain a child agent UUID argument", parentID)
		return
	}
	return
}
