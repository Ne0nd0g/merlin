// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package opaque

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"golang.org/x/crypto/pbkdf2"
	"time"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register(Opaque{})
}

const (
	RegInit        = 1
	RegComplete    = 2
	AuthInit       = 3
	AuthComplete   = 4
	ReRegister     = 5
	ReAuthenticate = 6
)

type Opaque struct {
	Type    int    // The type of OPAQUE message from the constants
	Payload []byte // OPAQUE payload data
}

type User struct {
	reg         *gopaque.UserRegister         // User Registration
	regComplete *gopaque.UserRegisterComplete // User Registration Complete
	auth        *gopaque.UserAuth             // User Authentication
	Kex         *gopaque.KeyExchangeSigma     // User Key Exchange
	pwdU        []byte                        // User Password
}

// registrationInit is used to register an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func registrationInit(agentID uuid.UUID, opaque Opaque, opaqueServerKey kyber.Scalar) (Opaque, error) {
	// TODO Make sure isAgent() is checked before making this call
	if core.Debug {
		message("debug", "Entering into opaque.RegistrationInit() function...")
	}

	logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration initialization from %s", agentID))

	var returnMessage Opaque

	_, ok := agents.Agents[agentID]
	if ok {
		return returnMessage, fmt.Errorf("the %s agent has already been registered", agentID)
	}

	serverReg := gopaque.NewServerRegister(gopaque.CryptoDefault, opaqueServerKey)
	var userRegInit gopaque.UserRegisterInit

	errUserRegInit := userRegInit.FromBytes(gopaque.CryptoDefault, opaque.Payload)
	if errUserRegInit != nil {
		return returnMessage, fmt.Errorf("there was an error unmarshalling the OPAQUE user register initialization message from bytes:\r\n%s", errUserRegInit)
	}

	if !bytes.Equal(userRegInit.UserID, agentID.Bytes()) {
		if core.Verbose {
			message("note", fmt.Sprintf("OPAQUE UserID: %v", userRegInit.UserID))
			message("note", fmt.Sprintf("Merlin Message UserID: %v", agentID.Bytes()))
		}
		return returnMessage, fmt.Errorf("the OPAQUE UserID doesn't match the Merlin message ID")
	}

	serverRegInit := serverReg.Init(&userRegInit)

	serverRegInitBytes, errServerRegInitBytes := serverRegInit.ToBytes()
	if errServerRegInitBytes != nil {
		return returnMessage, fmt.Errorf("there was an error marshalling the OPAQUE server registration initialization message to bytes:\r\n%s", errServerRegInitBytes)
	}

	returnMessage.Type = RegInit
	returnMessage.Payload = serverRegInitBytes

	// Create new agent and add it to the global map
	agent, agentErr := agents.New(agentID)
	if agentErr != nil {
		return returnMessage, fmt.Errorf("there was an error creating a new agent instance for %s:\r\n%s", agentID, agentErr)
	}
	agent.OPAQUEServerReg = *serverReg

	// Add agent to global map
	agents.Agents[agentID] = &agent

	agent.Log("Received agent OPAQUE register initialization message")

	if core.Debug {
		message("debug", "Leaving agents.OPAQUERegistrationInit function without error")
	}

	return returnMessage, nil
}

// registrationComplete is used to complete OPAQUE user registration and store the encrypted envelope EnvU
func registrationComplete(agentID uuid.UUID, opaque Opaque) (Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.registrationComplete function...")
	}
	returnMessage := Opaque{
		Type: RegComplete,
	}

	logging.Server(fmt.Sprintf("Received new agent OPAQUE user registration complete from %s", agentID))

	agent, ok := agents.Agents[agentID]
	if !ok {
		return returnMessage, fmt.Errorf("the %s agent has not completed OPAQUE user registration intialization", agentID)
	}

	var userRegComplete gopaque.UserRegisterComplete

	errUserRegComplete := userRegComplete.FromBytes(gopaque.CryptoDefault, opaque.Payload)
	if errUserRegComplete != nil {
		return returnMessage, fmt.Errorf("there was an error unmarshalling the OPAQUE user register complete message from bytes:\r\n%s", errUserRegComplete.Error())
	}

	agents.Agents[agentID].OPAQUERecord = *agents.Agents[agentID].OPAQUEServerReg.Complete(&userRegComplete)

	// Check to make sure Merlin  UserID matches OPAQUE UserID
	if !bytes.Equal(agentID.Bytes(), agents.Agents[agentID].OPAQUERecord.UserID) {
		return returnMessage, fmt.Errorf("the OPAQUE UserID: %v doesn't match the Merlin UserID: %v", agents.Agents[agentID].OPAQUERecord.UserID, agentID.Bytes())
	}

	agent.Log("OPAQUE registration complete")

	if core.Debug {
		message("debug", "Leaving opaque.registrationComplete function without error")
	}

	return returnMessage, nil
}

// authenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol and pre-shared key
func authenticateInit(agentID uuid.UUID, opaque Opaque) (Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.authenticateInit function...")
	}
	logging.Server(fmt.Sprintf("Received new agent OPAQUE authentication from %s", agentID))
	returnMessage := Opaque{
		Type: AuthInit,
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent does not exist and must re-register itself
		m := fmt.Sprintf("Un-Registered agent %s sent OPAQUE authentication, instructing agent to OPAQUE register", agentID)
		message("note", m) // TODO Should use messages API
		logging.Server(m)
		returnMessage.Type = ReRegister
		return returnMessage, nil
	}

	// 1 - Receive the user's UserAuthInit
	serverKex := gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	serverAuth := gopaque.NewServerAuth(gopaque.CryptoDefault, serverKex)
	agents.Agents[agentID].OPAQUEServerAuth = *serverAuth

	var userInit gopaque.UserAuthInit
	errFromBytes := userInit.FromBytes(gopaque.CryptoDefault, opaque.Payload)
	if errFromBytes != nil {
		message("warn", fmt.Sprintf("there was an error unmarshalling the user init message from bytes:\r\n%s", errFromBytes.Error()))
	}

	serverAuthComplete, errServerAuthComplete := serverAuth.Complete(&userInit, &agents.Agents[agentID].OPAQUERecord)

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
	agents.Agents[agentID].Secret = []byte(serverKex.SharedSecret.String())

	agent.Log("Received new agent OPAQUE authentication initialization message")

	if core.Debug {
		message("debug", fmt.Sprintf("Received new agent OPAQUE authentication for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339)))
		message("debug", "Leaving opaque.authenticateInit function without error")
		message("debug", fmt.Sprintf("Server OPAQUE key exchange shared secret: %v", agents.Agents[agentID].Secret))
	}
	return returnMessage, nil
}

// authenticateComplete is used to receive the OPAQUE UserAuthComplete
func authenticateComplete(agentID uuid.UUID, opaque Opaque) error {
	if core.Debug {
		message("debug", "Entering into opaque.authenticateComplete function")
	}
	m := fmt.Sprintf("New authenticated agent checkin for %s at %s", agentID, time.Now().UTC().Format(time.RFC3339))
	message("success", m)
	logging.Server(m)
	// check to see if this agent is already known to the server
	agent, ok := agents.Agents[agentID]
	if !ok {
		return fmt.Errorf("%s is not a known agent", agentID)
	}

	agent.Log("Received agent OPAQUE authentication complete message")

	var userComplete gopaque.UserAuthComplete
	errFromBytes := userComplete.FromBytes(gopaque.CryptoDefault, opaque.Payload)
	if errFromBytes != nil {
		message("warn", fmt.Sprintf("there was an error unmarshalling the user complete message from bytes:\r\n%s", errFromBytes.Error()))
	}

	// server auth finish
	errAuthFinish := agents.Agents[agentID].OPAQUEServerAuth.Finish(&userComplete)
	if errAuthFinish != nil {
		message("warn", fmt.Sprintf("there was an error finishing authentication:\r\n%s", errAuthFinish.Error()))
	}

	if core.Debug {
		message("debug", "Leaving opaque.authenticateComplete function without error")
	}
	return nil
}

// reAuthenticate is used when an agent has previously completed OPAQUE registration but needs to re-authenticate
func reAuthenticate(agentID uuid.UUID) (Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.reAuthenticate function...")
	}

	returnMessage := Opaque{
		Type: ReAuthenticate,
	}

	agent, ok := agents.Agents[agentID]
	if !ok {
		// Agent does not exist and must re-register itself
		returnMessage.Type = ReRegister
		return returnMessage, nil
	}

	agent.Log("Instructing agent to re-authenticate with OPAQUE protocol")

	if core.Debug {
		message("debug", "Leaving opaque.reAuthenticate function without error")
	}

	return returnMessage, nil
}

// Handles OPAQUE messages for authenticated agents
// Messages should only allow:
// AuthComplete
func Handler(agentID uuid.UUID, opaque Opaque) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into opaque.Handler() function...")
	}
	var err error
	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
		Type:    messages.OPAQUE,
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}
	switch opaque.Type {
	case AuthComplete:
		err = authenticateComplete(agentID, opaque)
		if err == nil {
			// Add AgentInfo job
			_, errAdd := jobs.Add(agentID, "agentInfo", []string{})
			if errAdd != nil {
				message("warn", fmt.Sprintf("there was an error adding the agentInfo job:\r\n%s", errAdd))
			}
			// Get job from queue
			jobs, err := jobs.Get(agentID)
			if err != nil {
				message("warn", err.Error())
			} else {
				returnMessage.Type = messages.JOBS
				returnMessage.Payload = jobs
			}
		}
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for authenticated handler: %d", opaque.Type))
	}
	if err != nil {
		return returnMessage, err
	}

	if core.Debug {
		message("debug", "Leaving opaque.Handler() function without error")
	}
	return returnMessage, nil
}

// UnAuthHandler accepts messages from an unauthenticated agent
// Messages should only allow:
// RegInit
// RegComplete
// AuthInit
func UnAuthHandler(agentID uuid.UUID, opaque Opaque, key kyber.Scalar) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into opaque.UnAuthHandler() function...")
	}
	if core.Verbose {
		message("note", fmt.Sprintf("Received OPAQUE message type: %d", opaque.Type))
	}
	var err error
	returnMessage := messages.Base{
		ID:      agentID,
		Version: 1.0,
		Type:    messages.OPAQUE,
		Padding: core.RandStringBytesMaskImprSrc(4096),
	}
	switch opaque.Type {
	case RegInit:
		returnMessage.Payload, err = registrationInit(agentID, opaque, key)
	case RegComplete:
		returnMessage.Payload, err = registrationComplete(agentID, opaque)
	case AuthInit:
		returnMessage.Payload, err = authenticateInit(agentID, opaque)
	case ReAuthenticate:
		returnMessage.Payload, err = reAuthenticate(agentID)
	default:
		err = fmt.Errorf(fmt.Sprintf("invalid OPAQUE type for un authenticated handler: %d", opaque.Type))
	}
	if err != nil {
		return returnMessage, err
	}

	if core.Debug {
		message("debug", "Leaving opaque.UnAuthHandler() function without error")
	}
	return returnMessage, nil
}

//RegisterInit is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration
func UserRegisterInit(AgentID uuid.UUID) (Opaque, *User, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserRegisterInit...")
	var user User
	// Generate a random password and run it through 5000 iterations of PBKDF2; Used with OPAQUE
	x := core.RandStringBytesMaskImprSrc(30)
	user.pwdU = pbkdf2.Key([]byte(x), AgentID.Bytes(), 5000, 32, sha256.New)

	// Build OPAQUE User Registration Initialization
	user.reg = gopaque.NewUserRegister(gopaque.CryptoDefault, AgentID.Bytes(), nil)
	userRegInit := user.reg.Init(user.pwdU)

	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE UserID: %x", userRegInit.UserID))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Alpha: %v", userRegInit.Alpha))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PwdU: %x", user.pwdU))

	userRegInitBytes, errUserRegInitBytes := userRegInit.ToBytes()
	if errUserRegInitBytes != nil {
		return Opaque{}, &user, fmt.Errorf("there was an error marshalling the OPAQUE user registration initialization message to bytes:\r\n%s", errUserRegInitBytes.Error())
	}

	// Message to be sent to the server
	regInit := Opaque{
		Type:    RegInit,
		Payload: userRegInitBytes,
	}

	return regInit, &user, nil
}

func UserRegisterComplete(regInitResp Opaque, user *User) (Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserRegisterComplete...")

	if regInitResp.Type != RegInit {
		return Opaque{}, fmt.Errorf("expected OPAQUE message type %d, got %d", RegInit, regInitResp.Type)
	}

	// Check to see if OPAQUE User Registration was previously completed
	if user.regComplete == nil {
		var serverRegInit gopaque.ServerRegisterInit

		errServerRegInit := serverRegInit.FromBytes(gopaque.CryptoDefault, regInitResp.Payload)
		if errServerRegInit != nil {
			return Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE server register initialization message from bytes:\r\n%s", errServerRegInit.Error())
		}

		cli.Message(cli.NOTE, "Received OPAQUE server registration initialization message")
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Beta: %v", serverRegInit.Beta))
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE V: %v", serverRegInit.V))
		cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubS: %s", serverRegInit.ServerPublicKey))

		// TODO extend gopaque to run RwdU through n iterations of PBKDF2
		user.regComplete = user.reg.Complete(&serverRegInit)
	}

	userRegCompleteBytes, errUserRegCompleteBytes := user.regComplete.ToBytes()
	if errUserRegCompleteBytes != nil {
		return Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user registration complete message to bytes:\r\n%s", errUserRegCompleteBytes.Error())
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE EnvU: %x", user.regComplete.EnvU))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubU: %v", user.regComplete.UserPublicKey))

	// message to be sent to the server
	regComplete := Opaque{
		Type:    RegComplete,
		Payload: userRegCompleteBytes,
	}

	return regComplete, nil
}

// UserAuthenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func UserAuthenticateInit(AgentID uuid.UUID, user *User) (Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserAuthenticateInit...")

	// 1 - Create a NewUserAuth with an embedded key exchange
	user.Kex = gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	user.auth = gopaque.NewUserAuth(gopaque.CryptoDefault, AgentID.Bytes(), user.Kex)

	// 2 - Call Init with the password and send the resulting UserAuthInit to the server
	userAuthInit, err := user.auth.Init(user.pwdU)
	if err != nil {
		return Opaque{}, fmt.Errorf("there was an error creating the OPAQUE user authentication initialization message:\r\n%s", err.Error())
	}

	userAuthInitBytes, errUserAuthInitBytes := userAuthInit.ToBytes()
	if errUserAuthInitBytes != nil {
		return Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user authentication initialization message to bytes:\r\n%s", errUserAuthInitBytes.Error())
	}

	// message to be sent to the server
	authInit := Opaque{
		Type:    AuthInit,
		Payload: userAuthInitBytes,
	}

	return authInit, nil
}

func UserAuthenticateComplete(authInitResp Opaque, user *User) (Opaque, error) {
	cli.Message(cli.DEBUG, "Entering into opaque.UserAuthenticateComplete...")

	if authInitResp.Type != AuthInit {
		return Opaque{}, fmt.Errorf("expected OPAQUE message type: %d, recieved: %d", AuthInit, authInitResp.Type)
	}

	// 3 - Receive the server's ServerAuthComplete
	var serverComplete gopaque.ServerAuthComplete

	errServerComplete := serverComplete.FromBytes(gopaque.CryptoDefault, authInitResp.Payload)
	if errServerComplete != nil {
		return Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE server complete message from bytes:\r\n%s", errServerComplete.Error())
	}

	// 4 - Call Complete with the server's ServerAuthComplete. The resulting UserAuthFinish has user and server key
	// information. This would be the last step if we were not using an embedded key exchange. Since we are, take the
	// resulting UserAuthComplete and send it to the server.
	cli.Message(cli.NOTE, "Received OPAQUE server complete message")
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE Beta: %x", serverComplete.Beta))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE V: %x", serverComplete.V))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE PubS: %x", serverComplete.ServerPublicKey))
	cli.Message(cli.DEBUG, fmt.Sprintf("OPAQUE EnvU: %x", serverComplete.EnvU))

	_, userAuthComplete, errUserAuth := user.auth.Complete(&serverComplete)
	if errUserAuth != nil {
		return Opaque{}, fmt.Errorf("there was an error completing OPAQUE authentication:\r\n%s", errUserAuth)
	}

	userAuthCompleteBytes, errUserAuthCompleteBytes := userAuthComplete.ToBytes()
	if errUserAuthCompleteBytes != nil {
		return Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE user authentication complete message to bytes:\r\n%s", errUserAuthCompleteBytes.Error())
	}

	authComplete := Opaque{
		Type:    AuthComplete,
		Payload: userAuthCompleteBytes,
	}

	return authComplete, nil
}

// message is used to send send messages to STDOUT where the server is running and not intended to be sent to CLI
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
