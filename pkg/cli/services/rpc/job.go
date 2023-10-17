/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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

	// 3rd Party
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/job"
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

// ClearJobs removes any jobs the queue for a specific Agent that have been created, but NOT sent to the agent
func ClearJobs(agentID uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.ClearJobs(context.Background(), &pb.ID{Id: agentID.String()}))
}

// ClearJobsCreated clears all created (but unsent) jobs for all agents
func ClearJobsCreated() (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.ClearJobsCreated(context.Background(), &emptypb.Empty{}))
}

// GetAgentActiveJobs returns all jobs from the RPC server for the specified Agent id
func GetAgentActiveJobs(id uuid.UUID) (jobs []job.Job, err error) {
	response, err := service.merlinClient.GetAgentActiveJobs(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAgentActiveJobs RPC method: %s", err)
		slog.Error(err.Error())
		return
	}
	for _, j := range response.Jobs {
		jobs = append(jobs, jobFromJobInfo(j))
	}
	return
}

// GetAllActiveJobs returns all Agent jobs from the RPC server that have not completed
func GetAllActiveJobs() (jobs []job.Job, err error) {
	response, err := service.merlinClient.GetAllActiveJobs(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAllActiveJobs RPC method: %s", err)
		slog.Error(err.Error())
		return
	}
	for _, j := range response.Jobs {
		jobs = append(jobs, jobFromJobInfo(j))
	}
	return
}

// GetAllJobs returns all Agent jobs from the RPC server
func GetAllJobs() (jobs []job.Job, err error) {
	response, err := service.merlinClient.GetAllJobs(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAllJobs RPC method: %s", err)
		return
	}
	for _, j := range response.Jobs {
		jobs = append(jobs, jobFromJobInfo(j))
	}
	return
}

// jobFromJobInfo converts a job protobuf message into a Job message structure used on the client
func jobFromJobInfo(j *pb.Job) job.Job {
	return job.Job{
		ID:        j.ID,
		AgentID:   j.AgentID,
		Command:   j.Command,
		Created:   j.Created,
		Completed: j.Completed,
		Status:    j.Status,
		Sent:      j.Sent,
	}
}
