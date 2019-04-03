// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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

package servers

import (
	// Standard
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	// 3rd Party
	"github.com/fatih/color"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/transport"
)

// Server is a structure for creating and instantiating new server objects
type Server struct {
	Interface   string
	Port        int
	Protocol    string
	Key         string
	Certificate string
	Server      interface{}
	Transport   transport.MerlinServerClient
	//Mux         *http.ServeMux
}

// New instantiates a new server object and returns it
func New(iface string, port int, protocol string, trn transport.MerlinServerClient) (Server, error) {
	s := Server{
		Protocol:  protocol,
		Interface: iface,
		Port:      port,
		Transport: trn.RegisterHandler(agentHandler),
	}
	return s, nil
}

// Run function starts the server on the preconfigured port for the preconfigured service
func (s Server) Run() error {
	return s.Transport.Run()
}

// agentHandler function is responsible for all Merlin agent traffic
func agentHandler(w io.Writer, r io.Reader) {
	var payload json.RawMessage
	j := messages.Base{
		Payload: &payload,
	}
	//reading the body before parsing json seems to resolve the receiving error on large bodies for some reason, unsure why
	b, e := ioutil.ReadAll(r)
	if e != nil {
		message("warn", fmt.Sprintf("There was an error reading a POST message sent by an "+
			"agent:\r\n%s", e))
		return
	}

	e = json.NewDecoder(bytes.NewReader(b)).Decode(&j)
	if e != nil {
		message("warn", fmt.Sprintf("There was an error decoding a POST message sent by an "+
			"agent:\r\n%s", e))
		return
	}
	if core.Debug {
		message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", j))
	}

	switch j.Type {

	case "InitialCheckIn":
		//var p messages.AgentInfo
		//json.Unmarshal(payload, &p)
		agents.InitialCheckIn(j)

	case "StatusCheckIn":
		//w.Header().Set("Content-Type", "application/json")
		x, err := agents.StatusCheckIn(j)
		if core.Verbose {
			message("note", fmt.Sprintf("Sending "+x.Type+" message type to agent"))
		}
		if err != nil {
			m := fmt.Sprintf("There was an error during an Agent StatusCheckIn:\r\n%s", err.Error())
			logging.Server(m)
			message("warn", m)
		}
		err2 := json.NewEncoder(w).Encode(x)
		if err2 != nil {
			m := fmt.Sprintf("There was an error encoding the StatusCheckIn JSON message:\r\n%s", err2.Error())
			logging.Server(m)
			message("warn", m)
			return
		}

	case "CmdResults":
		// TODO move to its own function
		var p messages.CmdResults
		err3 := json.Unmarshal(payload, &p)
		if err3 != nil {
			m := fmt.Sprintf("There was an error unmarshalling the CmdResults JSON object:\r\n%s", err3.Error())
			logging.Server(m)
			message("warn", m)
			return
		}
		agents.Log(j.ID, fmt.Sprintf("Results for job: %s", p.Job))

		message("success", fmt.Sprintf("Results for job %s at %s", p.Job, time.Now().UTC().Format(time.RFC3339)))
		if len(p.Stdout) > 0 {
			agents.Log(j.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
			color.Green(fmt.Sprintf("%s", p.Stdout))
		}
		if len(p.Stderr) > 0 {
			agents.Log(j.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
			color.Red(fmt.Sprintf("%s", p.Stderr))
		}

	case "AgentInfo":
		var p messages.AgentInfo
		err4 := json.Unmarshal(payload, &p)
		if err4 != nil {
			m := fmt.Sprintf("There was an error unmarshalling the AgentInfo JSON object:\r\n%s", err4.Error())
			logging.Server(m)
			message("warn", m)
			return
		}
		if core.Debug {
			message("debug", fmt.Sprintf("AgentInfo JSON object: %v", p))
		}
		agents.UpdateInfo(j, p)
	case "FileTransfer":
		var p messages.FileTransfer
		err5 := json.Unmarshal(payload, &p)
		if err5 != nil {
			m := fmt.Sprintf("There was an error unmarshalling the FileTransfer JSON object:\r\n%s", err5.Error())
			logging.Server(m)
			message("warn", m)
		}
		if p.IsDownload {
			agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
			_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
			if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
				m := fmt.Sprintf("There was an error locating the agent's directory:\r\n%s", errD.Error())
				logging.Server(m)
				message("warn", m)
			}
			message("success", fmt.Sprintf("Results for job %s", p.Job))
			downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

			if downloadBlobErr != nil {
				m := fmt.Sprintf("There was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
				logging.Server(m)
				message("warn", m)
			} else {
				downloadFile := filepath.Join(agentsDir, j.ID.String(), f)
				writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
				if writingErr != nil {
					m := fmt.Sprintf("There was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
					logging.Server(m)
					message("warn", m)
				} else {
					message("success", fmt.Sprintf("Successfully downloaded file %s with a size of "+
						"%d bytes from agent %s to %s",
						p.FileLocation,
						len(downloadBlob),
						j.ID.String(),
						downloadFile))
					agents.Log(j.ID, fmt.Sprintf("Successfully downloaded file %s with a size of %d "+
						"bytes from agent to %s",
						p.FileLocation,
						len(downloadBlob),
						downloadFile))
				}
			}
		}
	default:
		message("warn", fmt.Sprintf("Invalid Activity: %s", j.Type))
	}
}

// message is used to print a message to the command line
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

// TODO make sure all errors are logged to server log
