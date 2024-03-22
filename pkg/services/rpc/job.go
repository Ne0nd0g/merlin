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

package rpc

import (
	// Standard
	"context"
	"fmt"
	"log/slog"
	"time"

	// 3rd Party
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/jobs"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

/* RPC METHODS TO INTERACT WITH THE JOB SERVICE */

// addJob validates that provided UUID is valid and then adds the job to the job service
func addJob(agentID string, jobType string, jobArgs []string) (msg *pb.Message, err error) {
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", agentID, err)
		slog.Error(err.Error())
		return
	}
	// Add the job
	var result string
	result, err = service.rpcServer.jobService.Add(agentUUID, jobType, jobArgs)
	if err != nil {
		err = fmt.Errorf("there was an error adding the '%s' job: %s", jobType, err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBNoteMessage(result)
	return
}

// ClearJobs removes any jobs the queue for a specific Agent that have been created, but NOT sent to the agent
func (s *Server) ClearJobs(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentUUID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id, err)
		return
	}
	err = s.jobService.Clear(agentUUID)
	if err == nil {
		msg = NewPBSuccessMessage(fmt.Sprintf("Cleared all jobs for agent %s", id.Id))
	}
	return
}

// ClearJobsCreated clears all created (but unsent) jobs for all agents
func (s *Server) ClearJobsCreated(ctx context.Context, e *emptypb.Empty) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	msg = &pb.Message{}
	err = s.jobService.ClearAll()
	if err == nil {
		msg = NewPBSuccessMessage("Cleared all created jobs")
	}
	return
}

// GetAgentActiveJobs returns all jobs that have not completed for the specified Agent
func (s *Server) GetAgentActiveJobs(ctx context.Context, id *pb.ID) (*pb.Jobs, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	returnJobs := &pb.Jobs{}
	// Parse the UUID from the request
	agentID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return returnJobs, err
	}
	agentJobs, err := s.jobService.GetAgentActive(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting agent %s's active jobs: %s", agentID, err)
		slog.Error(err.Error())
		return returnJobs, err
	}
	for _, jobInfo := range agentJobs {
		j := s.jobToJobInfo(jobInfo)
		returnJobs.Jobs = append(returnJobs.Jobs, j)
	}
	return returnJobs, nil
}

// GetAllActiveJobs returns all Agent jobs that have not completed
func (s *Server) GetAllActiveJobs(ctx context.Context, e *emptypb.Empty) (*pb.Jobs, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	returnJobs := &pb.Jobs{}
	for _, jobInfo := range s.jobService.GetAllActive() {
		j := s.jobToJobInfo(jobInfo)
		returnJobs.Jobs = append(returnJobs.Jobs, j)
	}
	return returnJobs, nil
}

// GetAllJobs returns all Agent jobs from the server
func (s *Server) GetAllJobs(ctx context.Context, e *emptypb.Empty) (*pb.Jobs, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	returnJobs := &pb.Jobs{}
	for _, jobInfo := range s.jobService.GetAll() {
		j := s.jobToJobInfo(jobInfo)
		returnJobs.Jobs = append(returnJobs.Jobs, j)
	}
	return returnJobs, nil
}

// jobToJobInfo converts a server-side Job Info structure into a protobuf Job structure
func (s *Server) jobToJobInfo(job jobs.Info) *pb.Job {
	slog.Log(context.Background(), logging.LevelTrace, "job info", "Job", fmt.Sprintf("%+v", job))
	j := &pb.Job{
		ID:      job.ID(),
		AgentID: job.AgentID().String(),
		Command: job.Command(),
		Created: job.Created().Format(time.RFC3339),
		Status:  job.StatusString(),
	}
	if !time.Time.IsZero(job.Sent()) {
		j.Sent = job.Sent().Format(time.RFC3339)
	}
	if !time.Time.IsZero(job.Completed()) {
		j.Completed = job.Completed().Format(time.RFC3339)
	}
	return j
}
