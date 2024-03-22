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

// Package memory is an in-memory repository for storing and managing Agent Jobs and associated Job tracking structures
package memory

import (
	// Standard
	"fmt"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	jobs2 "github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/jobs"
)

// Repository is the structure that implements the in-memory repository for interacting with Agent Jobs
type Repository struct {
	sync.Mutex
	jobsChannel map[uuid.UUID]chan jobs2.Job // jobsChannel contains all outgoing Jobs that need to be sent to an Agent
	jobs        map[string]jobs.Info         // jobs is a map of all Job Info tracking structures
}

// repo is the in-memory datastore
var repo *Repository

// NewRepository creates and returns a new in-memory repository for interacting with Agent Jobs
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			Mutex:       sync.Mutex{},
			jobsChannel: make(map[uuid.UUID]chan jobs2.Job),
			jobs:        make(map[string]jobs.Info),
		}
	}
	return repo
}

// Add the Job and associated Info tracking structure to the repository
func (r *Repository) Add(job jobs2.Job, info jobs.Info) {
	r.Lock()
	// Check to see if a job channel for the agent exist
	_, k := r.jobsChannel[job.AgentID]
	// Create a job channel for the agent if one does not exist
	if !k {
		r.jobsChannel[job.AgentID] = make(chan jobs2.Job, 100)
	}

	// Add job to the agent's job channel
	r.jobsChannel[job.AgentID] <- job

	// Add Info
	r.jobs[job.ID] = info

	r.Unlock()
}

// Clear removes all Jobs that have not already been sent to the associated Agent
func (r *Repository) Clear(agentID uuid.UUID) error {
	r.Lock()
	defer r.Unlock()
	jobChannel, ok := r.jobsChannel[agentID]
	if !ok {
		return fmt.Errorf("pkg/jobs/memory.Get(): a channel key for Agent %s does not exist", agentID)
	}

	jobLength := len(jobChannel)
	if jobLength > 0 {
		// Empty the job channel
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			// Update Job Info structure
			j, ok := r.jobs[job.ID]
			if ok {
				j.Cancel()
				r.jobs[job.ID] = j
			} else {
				return fmt.Errorf("invalid job %s for agent %s", job.ID, agentID)
			}
		}
	}
	return nil
}

// ClearAll removes all Jobs that have not already been sent for ALL Agents
func (r *Repository) ClearAll() error {
	for id := range r.jobsChannel {
		err := r.Clear(id)
		if err != nil {
			return fmt.Errorf("pkg/jobs/memory.ClearAll(): %s", err)
		}
	}
	return nil
}

// GetAll returns all Job Info tracking structures as map to be iterated over
func (r *Repository) GetAll() map[string]jobs.Info {
	return r.jobs
}

// GetInfo returns the Job Info tracking structure for the associate Job ID
func (r *Repository) GetInfo(jobID string) (jobs.Info, error) {
	info, ok := r.jobs[jobID]
	if !ok {
		return info, fmt.Errorf("pkg/jobs/memory.GetInfo(): unable to find structure for job %s", jobID)
	}
	return info, nil
}

// GetJobs returns all jobs waiting to be sent to the associated Agent
func (r *Repository) GetJobs(agentID uuid.UUID) (jobs []jobs2.Job, err error) {
	r.Lock()
	defer r.Unlock()
	jobChannel, ok := r.jobsChannel[agentID]
	if !ok {
		err = fmt.Errorf("pkg/jobs/memory.Get(): a channel key for Agent %s does not exist", agentID)
		return
	}

	// If there are any jobs in the channel, return them
	jobLength := len(jobChannel)
	if jobLength > 0 {
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			jobs = append(jobs, job)

			// Update Job Info map
			info, exists := r.jobs[job.ID]
			if exists {
				info.Send()
				r.jobs[job.ID] = info
			} else {
				return jobs, fmt.Errorf("invalid job %s for agent %s", job.ID, agentID)
			}
		}
	}
	return
}

// UpdateInfo replaces the Job Info tracking structure with the one provided
func (r *Repository) UpdateInfo(info jobs.Info) error {
	r.Lock()
	defer r.Unlock()
	if _, ok := r.jobs[info.ID()]; !ok {
		return fmt.Errorf("pkg/jobs/memory.UpdateInfo(): unable to find structure for job %s", info.ID())
	}
	r.jobs[info.ID()] = info
	return nil
}
