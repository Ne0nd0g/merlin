// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/satori/go.uuid"

	// Merlin
	messageAPI "github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/pkg/opaque"
)

// Global Variables

// Agents contains all of the instantiated agent object that are accessed by other modules
var Agents = make(map[uuid.UUID]*Agent)

// groups map agent(s) to a string for bulk access
var groups = make(map[string][]uuid.UUID)

func init() {
	globalUUID, err := uuid.FromString("ffffffff-ffff-ffff-ffff-ffffffffffff")
	if err == nil {
		groups["all"] = []uuid.UUID{globalUUID}
	}
}

// Agent is a server side structure that holds information about a Merlin Agent
type Agent struct {
	ID             uuid.UUID
	Platform       string
	Architecture   string
	UserName       string
	UserGUID       string
	HostName       string
	Integrity      int
	Ips            []string
	Pid            int
	Process        string
	agentLog       *os.File
	InitialCheckIn time.Time
	StatusCheckIn  time.Time
	Version        string
	Build          string
	WaitTime       string
	PaddingMax     int
	MaxRetry       int
	FailedCheckin  int
	Skew           int64
	Proto          string
	KillDate       int64
	RSAKeys        *rsa.PrivateKey // RSA Private/Public key pair; Private key used to decrypt messages
	PublicKey      rsa.PublicKey   // Public key used to encrypt messages
	Secret         []byte          // secret is used to perform symmetric encryption operations
	OPAQUE         *opaque.Server  // Holds information about OPAQUE Registration and Authentication
	JA3            string          // The JA3 signature applied to the agent's TLS client
	Note           string          // Operator notes for an agent
}

// KeyExchange is used to exchange public keys between the server and agent
func KeyExchange(m messages.Base) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into agents.KeyExchange function")
	}

	serverKeyMessage := messages.Base{
		ID:      m.ID,
		Version: 1.0,
		Type:    messages.KEYEXCHANGE,
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

// GetEncryptionKey retrieves the per-agent payload encryption key used to decrypt messages for any protocol
func GetEncryptionKey(agentID uuid.UUID) ([]byte, error) {
	if core.Debug {
		message("debug", "Entering into agents.GetEncryptionKey function")
	}

	if !isAgent(agentID) {
		return nil, fmt.Errorf("agent %s does not exist", agentID)
	}
	key := Agents[agentID].Secret
	if len(key) <= 0 {
		return nil, fmt.Errorf("the encryption key for %s is empty", agentID)
	}
	if core.Debug {
		message("debug", "Leaving agents.GetEncryptionKey function")
	}
	return key, nil
}

// UpdateInfo is used to update an agent's information with the passed in message data
func (a *Agent) UpdateInfo(info messages.AgentInfo) {
	if core.Debug {
		message("debug", "Entering into agents.UpdateInfo function")
	}

	if core.Debug {
		message("debug", fmt.Sprintf("Processing new agent info:\n%+v", info))
	}

	a.Log("Processing AgentInfo message:")
	a.Log(fmt.Sprintf("\tAgent Version: %s ", info.Version))
	a.Log(fmt.Sprintf("\tAgent Build: %s ", info.Build))
	a.Log(fmt.Sprintf("\tAgent waitTime: %s ", info.WaitTime))
	a.Log(fmt.Sprintf("\tAgent skew: %d ", info.Skew))
	a.Log(fmt.Sprintf("\tAgent paddingMax: %d ", info.PaddingMax))
	a.Log(fmt.Sprintf("\tAgent maxRetry: %d ", info.MaxRetry))
	a.Log(fmt.Sprintf("\tAgent failedCheckin: %d ", info.FailedCheckin))
	a.Log(fmt.Sprintf("\tAgent proto: %s ", info.Proto))
	a.Log(fmt.Sprintf("\tAgent KillDate: %s", time.Unix(a.KillDate, 0).UTC().Format(time.RFC3339)))
	a.Log(fmt.Sprintf("\tAgent JA3 signature: %s", info.JA3))

	a.Version = info.Version
	a.Build = info.Build
	a.WaitTime = info.WaitTime
	a.Skew = info.Skew
	a.PaddingMax = info.PaddingMax
	a.MaxRetry = info.MaxRetry
	a.FailedCheckin = info.FailedCheckin
	a.Proto = info.Proto
	a.KillDate = info.KillDate
	a.JA3 = info.JA3

	a.Architecture = info.SysInfo.Architecture
	a.HostName = info.SysInfo.HostName
	a.Process = info.SysInfo.Process
	a.Pid = info.SysInfo.Pid
	a.Ips = info.SysInfo.Ips
	a.Platform = info.SysInfo.Platform
	a.UserName = info.SysInfo.UserName
	a.UserGUID = info.SysInfo.UserGUID
	a.Integrity = info.SysInfo.Integrity

	if core.Debug {
		message("debug", "Leaving agents.UpdateInfo function")
	}
}

// Log is used to write log messages to the agent's log file
func (a *Agent) Log(logMessage string) {
	if core.Debug {
		message("debug", "Entering into agents.Log")
	}
	_, err := a.agentLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), logMessage))
	if err != nil {
		message("warn", fmt.Sprintf("There was an error writing to the agent log agents.Log:\r\n%s", err.Error()))
	}
}

// message is used to send a broadcast message to all connected clients
func message(level string, message string) {
	m := messageAPI.UserMessage{
		Message: message,
		Time:    time.Now().UTC(),
		Error:   false,
	}
	switch level {
	case "info":
		m.Level = messageAPI.Info
	case "note":
		m.Level = messageAPI.Note
	case "warn":
		m.Level = messageAPI.Warn
	case "debug":
		m.Level = messageAPI.Debug
	case "success":
		m.Level = messageAPI.Success
	case "plain":
		m.Level = messageAPI.Plain
	default:
		m.Level = messageAPI.Plain
	}
	messageAPI.SendBroadcastMessage(m)
}

// RemoveAgent deletes the agent object from Agents map by its ID
func RemoveAgent(agentID uuid.UUID) error {
	if isAgent(agentID) {
		delete(Agents, agentID)
		return nil
	}
	return fmt.Errorf("%s is not a known agent and was not removed", agentID)
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

// New creates a new Agent and returns the object but does not add it to the global agents map
func New(agentID uuid.UUID) (Agent, error) {
	if core.Debug {
		message("debug", "Entering into agents.newAgent function")
	}
	var agent Agent
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
		errChmod := os.Chmod(agentLog.Name(), 0600)
		if errChmod != nil {
			return agent, fmt.Errorf("there was an error changing the file permissions for the agent log:\r\n%s", errChmod.Error())
		}

		if core.Verbose {
			message("note", fmt.Sprintf("Created agent log file at: %s agent_log.txt",
				path.Join(agentsDir, agentID.String())))
		}
	}
	// Open agent's log file for writing
	f, err := os.OpenFile(filepath.Clean(filepath.Join(agentsDir, agentID.String(), "agent_log.txt")), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return agent, fmt.Errorf("there was an error openeing the %s agent's log file:\r\n%s", agentID.String(), err.Error())
	}

	agent.ID = agentID
	agent.agentLog = f
	agent.InitialCheckIn = time.Now().UTC()
	agent.StatusCheckIn = time.Now().UTC()

	_, errAgentLog := agent.agentLog.WriteString(fmt.Sprintf("[%s]%s\r\n", time.Now().UTC().Format(time.RFC3339), "Instantiated agent"))
	if errAgentLog != nil {
		message("warn", fmt.Sprintf("There was an error writing to the agent log agents.Log:\r\n%s", errAgentLog.Error()))
	}

	if core.Debug {
		message("debug", "Leaving agents.newAgent function without error")
	}
	return agent, nil
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

// SetWaitTime updates an Agent's sleep amount or Wait Time
func SetWaitTime(agentID uuid.UUID, wait string) error {
	if isAgent(agentID) {
		_, err := time.ParseDuration(wait)
		if err != nil {
			return fmt.Errorf("there was an error parsing %s to a duration for the Agent's WaitTime:\r\n%s", wait, err)
		}
		Agents[agentID].WaitTime = wait
		return nil
	}
	return fmt.Errorf("the %s Agent is unknown", agentID.String())
}

// SetMaxRetry updates an Agent's MaxRetry limit
func SetMaxRetry(agentID uuid.UUID, retry string) error {
	if isAgent(agentID) {
		r, err := strconv.Atoi(retry)
		if err != nil {
			return fmt.Errorf("there was an error converting %s to an integer for Agent %s:\n%s", retry, agentID, err)
		}
		Agents[agentID].MaxRetry = r
		return nil
	}
	return fmt.Errorf("the %s Agent is unknown", agentID.String())
}

// SetAgentNote updates the agent's note field
func SetAgentNote(agentID uuid.UUID, note string) error {
	if !isAgent(agentID) {
		return fmt.Errorf("%s is not a known agent", agentID)
	}
	Agents[agentID].Note = note
	return nil
}

// GroupAddAgent adds an agent to a group
func GroupAddAgent(agentID uuid.UUID, groupName string) error {
	if !isAgent(agentID) {
		return fmt.Errorf("%s is not a known agent", agentID)
	}
	grp, ok := groups[groupName]
	if !ok {
		groups[groupName] = []uuid.UUID{agentID}
	} else {
		// Don't add it to the group if it's already there
		for _, a := range groups[groupName] {
			if uuid.Equal(a, agentID) {
				return nil
			}
		}
		groups[groupName] = append(grp, agentID)
	}
	return nil
}

// GroupListAll lists groups as a table of {groupName,agentID}
func GroupListAll() [][]string {
	var out [][]string
	for groupName, agentIDs := range groups {
		for _, aID := range agentIDs {
			out = append(out, []string{groupName, aID.String()})
		}
	}
	return out
}

// GroupListNames list out just the names of existing groups
func GroupListNames() []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	return keys
}

// GroupRemoveAgent removes an agent from a group
func GroupRemoveAgent(agentID uuid.UUID, groupName string) error {
	if !isAgent(agentID) {
		return fmt.Errorf("%s is not a known agent", agentID)
	}

	grp, ok := groups[groupName]
	if !ok {
		return fmt.Errorf("%s is not a group", groupName)
	}

	tmp := grp[:0]
	for _, a := range grp {
		if !uuid.Equal(a, agentID) {
			tmp = append(tmp, a)
		}
	}
	groups[groupName] = tmp

	//Make sure to delete group if empty
	if len(groups[groupName]) == 0 {
		delete(groups, groupName)
	}

	return nil
}
