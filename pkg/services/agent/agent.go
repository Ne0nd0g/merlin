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

// Package agent is the service for interacting with Agent objects
package agent

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
	"github.com/Ne0nd0g/merlin/v2/pkg/agents/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/group"
	groupMemory "github.com/Ne0nd0g/merlin/v2/pkg/group/memory"
)

// Service holds references to repositories to manage Agent objects or Group objects
type Service struct {
	agentRepo agents.Repository
	groupRepo group.Repository
}

// memoryService is an in-memory instantiation of the Agent service so that it can be used by others
var memoryService *Service

// NewAgentService is a factory to create an Agent service to be used by other packages or services
func NewAgentService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			agentRepo: WithMemoryAgentRepository(),
			groupRepo: WithMemoryGroupRepository(),
		}
	}
	return memoryService
}

// WithMemoryAgentRepository retrieves an in-memory Agent repository interface used to manage Agent object
func WithMemoryAgentRepository() agents.Repository {
	return memory.NewRepository()
}

// WithMemoryGroupRepository retrieves an in-memory Group repository interface used to manage Agent Group object
func WithMemoryGroupRepository() group.Repository {
	return groupMemory.NewRepository()
}

/* AGENT FUNCTIONS */

// Add stores and Agent object in the database
func (s *Service) Add(agent agents.Agent) (err error) {
	err = s.agentRepo.Add(agent)
	if err != nil {
		return err
	}
	slog.Debug(fmt.Sprintf("Added Agent %s to the repository", agent.ID()))
	return
}

// Agent returns a single Agent object for the provided id
func (s *Service) Agent(id uuid.UUID) (agents.Agent, error) {
	return s.agentRepo.Get(id)
}

// Agents returns a list of all Agent objects known to the server
func (s *Service) Agents() []agents.Agent {
	return s.agentRepo.GetAll()
}

// Authenticated determines if the Agent is authenticated or not
func (s *Service) Authenticated(id uuid.UUID) bool {
	agent, err := s.Agent(id)
	if err != nil {
		return false
	}
	return agent.Authenticated()
}

// Exist determines if the Agent is known to the server or not
func (s *Service) Exist(id uuid.UUID) bool {
	_, err := s.Agent(id)
	if err != nil {
		return false
	}
	return true
}

// Lifetime returns the amount an agent could live without successfully communicating with the server
func (s *Service) Lifetime(id uuid.UUID) (time.Duration, error) {
	agent, err := s.agentRepo.Get(id)
	if err != nil {
		return 0, err
	}

	comms := agent.Comms()

	sleep, err := time.ParseDuration(comms.Wait)
	if err != nil {
		return 0, fmt.Errorf("pkg/services/agent.Lifetime(): there was an error parsing the agent WaitTime to a duration: %s", err)
	}
	if sleep == 0 {
		return 0, fmt.Errorf("agent WaitTime is equal to zero")
	}

	if comms.Retry == 0 {
		return 0, fmt.Errorf("agent MaxRetry is equal to zero")
	}

	skew := time.Duration(comms.Skew) * time.Millisecond

	// Calculate the worst case scenario that an agent could be alive before dying
	lifetime := sleep + skew
	for comms.Retry > 1 {
		lifetime = lifetime + (sleep + skew)
		comms.Retry--
	}

	if comms.Kill > 0 {
		if time.Now().Add(lifetime).After(time.Unix(comms.Kill, 0)) {
			return 0, fmt.Errorf("the agent lifetime will exceed the killdate")
		}
	}
	return lifetime, nil
}

// Link adds a child relationship link to the Agent id
func (s *Service) Link(id, link uuid.UUID) error {
	return s.agentRepo.AddLinkedAgent(id, link)
}

// Links returns a list of child Agent IDs
func (s *Service) Links(id uuid.UUID) ([]uuid.UUID, error) {
	agent, err := s.Agent(id)
	if err != nil {
		return []uuid.UUID{}, err
	}
	return agent.Links(), nil
}

// Linked determines if the link is associated with the parent agent id
func (s *Service) Linked(id, link uuid.UUID) (bool, error) {
	agent, err := s.Agent(id)
	if err != nil {
		return false, err
	}
	for _, l := range agent.Links() {
		if l == link {
			return true, nil
		}
	}
	return false, nil
}

// Log writes a message to an existing Agent's log file
func (s *Service) Log(id uuid.UUID, message string) error {
	return s.agentRepo.Log(id, message)
}

// IsChild checks to see if the Agent id is a peer-to-peer child to any other Agent
func (s *Service) IsChild(id uuid.UUID) bool {
	theseAgents := s.Agents()
	for _, agent := range theseAgents {
		links, err := s.Links(agent.ID())
		if err != nil {
			return false
		}
		for _, link := range links {
			if link == id {
				return true
			}
		}
	}
	return false
}

// Remove deletes an existing Agent from the database
func (s *Service) Remove(id uuid.UUID) (err error) {
	err = s.agentRepo.Remove(id)
	if err != nil {
		return
	}
	slog.Info(fmt.Sprintf("Removed Agent %s from the repository", id))
	return
}

// ResetAuthentication sets the Agent's authentication status to false and its secret back to empty
func (s *Service) ResetAuthentication(id uuid.UUID) (err error) {
	var agent agents.Agent
	agent, err = s.agentRepo.Get(id)
	if err != nil {
		return err
	}
	agent.UpdateAuthenticated(false)
	agent.SetSecret([]byte{})
	agent.ResetOPAQUE()
	return s.Update(agent)
}

// Status determines if the agent is active, delayed, or dead based on its last checkin time and retry settings
func (s *Service) Status(id uuid.UUID) (status string, err error) {
	var agent agents.Agent
	agent, err = s.Agent(id)
	if err != nil {
		return "", err
	}

	var d time.Duration
	d, err = time.ParseDuration(agent.Comms().Wait)

	if err != nil && agent.Comms().Wait != "" {
		err = fmt.Errorf("there was an error converting %s to a time duration: %s", agent.Comms().Wait, err)
	}
	// Clear the error
	err = nil
	if agent.Comms().Wait == "" {
		status = "Init"
	} else if agent.StatusCheckin().Add(d).After(time.Now()) {
		status = "Active"
	} else if agent.StatusCheckin().Add(d * time.Duration(agent.Comms().Retry+1)).After(time.Now()) { // +1 to account for skew
		status = "Delayed"
	} else {
		status = "Dead"
	}
	return
}

// Unlink removes a child Agent link from the parent Agent id
func (s *Service) Unlink(id, link uuid.UUID) error {
	return s.agentRepo.RemoveLinkedAgent(id, link)
}

// Update replaces an Agent object in the database with the one provided
func (s *Service) Update(agent agents.Agent) error {
	return s.agentRepo.Update(agent)
}

// UpdateAgentInfo replaces an existing Agent's embedded Build, Comms, Host, and Process structures
// This is typically used after initial checkin or when the Agent has a configuration change
func (s *Service) UpdateAgentInfo(id uuid.UUID, info messages.AgentInfo) (err error) {
	agent, err := s.Agent(id)
	if err != nil {
		return err
	}
	agent.Log(fmt.Sprintf("AgentInfo: %+v", info))

	// Build
	build := agents.Build{
		Build:   info.Build,
		Version: info.Version,
	}
	err = s.agentRepo.UpdateBuild(id, build)
	if err != nil {
		return
	}

	// Comms
	comms := agents.Comms{
		Failed:  info.FailedCheckin,
		JA3:     info.JA3,
		Kill:    info.KillDate,
		Padding: info.PaddingMax,
		Proto:   info.Proto,
		Retry:   info.MaxRetry,
		Skew:    info.Skew,
		Wait:    info.WaitTime,
	}

	err = s.agentRepo.UpdateComms(id, comms)
	if err != nil {
		return
	}

	// Host
	host := agents.Host{
		Architecture: info.SysInfo.Architecture,
		Name:         info.SysInfo.HostName,
		Platform:     info.SysInfo.Platform,
		IPs:          info.SysInfo.Ips,
	}
	err = s.agentRepo.UpdateHost(id, host)
	if err != nil {
		return
	}

	// Process
	process := agents.Process{
		ID:        info.SysInfo.Pid,
		Integrity: info.SysInfo.Integrity,
		Name:      info.SysInfo.Process,
		UserGUID:  info.SysInfo.UserGUID,
		UserName:  info.SysInfo.UserName,
		Domain:    info.SysInfo.Domain,
	}
	err = s.agentRepo.UpdateProcess(id, process)

	return
}

// UpdateAlive set's the Agent's alive status to the provided value
func (s *Service) UpdateAlive(id uuid.UUID, alive bool) error {
	return s.agentRepo.UpdateAlive(id, alive)
}

// UpdateAuthenticated set's the Agent's authenticated field value
func (s *Service) UpdateAuthenticated(id uuid.UUID, authenticated bool) error {
	return s.agentRepo.UpdateAuthenticated(id, authenticated)
}

// UpdateComms replaces an existing Agent's embedded Comms structure
func (s *Service) UpdateComms(id uuid.UUID, comms agents.Comms) error {
	return s.agentRepo.UpdateComms(id, comms)
}

// UpdateInitial set's that Agent's initial checkin time field
func (s *Service) UpdateInitial(id uuid.UUID, t time.Time) error {
	return s.agentRepo.UpdateInitial(id, t)
}

func (s *Service) UpdateListener(id, listener uuid.UUID) error {
	return s.agentRepo.UpdateListener(id, listener)
}

// UpdateNote replaces an existing Agent's note
func (s *Service) UpdateNote(id uuid.UUID, note string) (err error) {
	return s.agentRepo.UpdateNote(id, note)
}

// UpdateStatusCheckin sets an existing Agent's timestamp for the last checkin field
func (s *Service) UpdateStatusCheckin(id uuid.UUID, t time.Time) error {
	return s.agentRepo.UpdateStatusCheckin(id, t)
}

/* GROUP FUNCTIONS */

// AddAgentToGroup adds the Agent to a group
func (s *Service) AddAgentToGroup(group string, id uuid.UUID) error {
	return s.groupRepo.AddAgent(group, id)
}

// Groups returns a list of all created groups
func (s *Service) Groups() []string {
	return s.groupRepo.Groups()
}

// GroupMembers returns a list of lists that contain all groups and their members
func (s *Service) GroupMembers() map[string][]uuid.UUID {
	members := s.groupRepo.Members()
	// Update the "all" group
	members["all"] = []uuid.UUID{}
	allAgents := s.Agents()
	for _, agent := range allAgents {
		members["all"] = append(members["all"], agent.ID())
	}
	return members
}

// RemoveAgentFromGroup removes an Agent ID from a group
func (s *Service) RemoveAgentFromGroup(group string, id uuid.UUID) error {
	return s.groupRepo.RemoveAgent(group, id)
}
