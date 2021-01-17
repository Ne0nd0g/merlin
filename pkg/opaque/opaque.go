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

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/pbkdf2"

	// Internal"
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/core"
)

// init registers message types with gob that are an interface for Base.Payload
func init() {
	gob.Register(Opaque{})
}

const (
	// RegInit is used to denote that the embedded payload contains data for the OPAQUE protocol Registration Initialization step
	RegInit = 1
	// RegComplete is used to denote that the embedded payload contains data for the OPAQUE protocol Registration Complete step
	RegComplete = 2
	// AuthInit is used to denote that the embedded payload contains data for the OPAQUE protocol Authorization Initialization step
	AuthInit = 3
	// AuthComplete is used to denote that the embedded payload contains data for the OPAQUE protocol Authorization Complete step
	AuthComplete = 4
	// ReRegister is used to instruct the Agent it needs to execute the OPAQUE Registration process with the server
	ReRegister = 5
	// ReAuthenticate is used to instruct the Agent it needs to execute the OPAQUE Authentication process with the server
	ReAuthenticate = 6
)

// Opaque is a structure that is embedded into Merlin messages as a payload used to complete OPAQUE registration and authentication
type Opaque struct {
	Type    int    // The type of OPAQUE message from the constants
	Payload []byte // OPAQUE payload data
}

// Server is the structure that holds information for the various steps of the OPAQUE protocol as the server
type Server struct {
	reg         *gopaque.ServerRegister
	regComplete *gopaque.ServerRegisterComplete
	auth        *gopaque.ServerAuth
	Kex         *gopaque.KeyExchangeSigma
}

// User is the structure that holds information for the various steps of the OPAQUE protocol as the user
type User struct {
	reg         *gopaque.UserRegister         // User Registration
	regComplete *gopaque.UserRegisterComplete // User Registration Complete
	auth        *gopaque.UserAuth             // User Authentication
	Kex         *gopaque.KeyExchangeSigma     // User Key Exchange
	pwdU        []byte                        // User Password
}

// ServerRegisterInit is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration steps for the server
func ServerRegisterInit(AgentID uuid.UUID, o Opaque, key kyber.Scalar) (Opaque, *Server, error) {
	if core.Debug {
		message("debug", "Entering into opaque.ServerRegisterInit() function...")
	}
	server := Server{
		reg: gopaque.NewServerRegister(gopaque.CryptoDefault, key),
	}
	var userRegInit gopaque.UserRegisterInit

	errUserRegInit := userRegInit.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errUserRegInit != nil {
		return Opaque{}, &server, fmt.Errorf("there was an error unmarshalling the OPAQUE user register initialization message from bytes:\r\n%s", errUserRegInit)
	}

	if !bytes.Equal(userRegInit.UserID, AgentID.Bytes()) {
		if core.Verbose {
			message("note", fmt.Sprintf("OPAQUE UserID: %v", userRegInit.UserID))
			message("note", fmt.Sprintf("Merlin Message UserID: %v", AgentID.Bytes()))
		}
		return Opaque{}, &server, fmt.Errorf("the OPAQUE UserID doesn't match the Merlin message ID")
	}

	serverRegInit := server.reg.Init(&userRegInit)

	serverRegInitBytes, errServerRegInitBytes := serverRegInit.ToBytes()
	if errServerRegInitBytes != nil {
		return Opaque{}, &server, fmt.Errorf("there was an error marshalling the OPAQUE server registration initialization message to bytes:\r\n%s", errServerRegInitBytes)
	}

	returnMessage := Opaque{
		Type:    RegInit,
		Payload: serverRegInitBytes,
	}

	return returnMessage, &server, nil
}

// ServerRegisterComplete consumes the User's response and finishes OPAQUE Registration
func ServerRegisterComplete(AgentID uuid.UUID, o Opaque, server *Server) (Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.ServerRegisterComplete() function...")
	}

	var userRegComplete gopaque.UserRegisterComplete

	errUserRegComplete := userRegComplete.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errUserRegComplete != nil {
		return Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE user register complete message from bytes:\r\n%s", errUserRegComplete.Error())
	}

	server.regComplete = server.reg.Complete(&userRegComplete)

	// Check to make sure Merlin  UserID matches OPAQUE UserID
	if !bytes.Equal(AgentID.Bytes(), server.regComplete.UserID) {
		return Opaque{}, fmt.Errorf("the OPAQUE UserID: %v doesn't match the Merlin UserID: %v", server.regComplete.UserID, AgentID.Bytes())
	}

	returnMessage := Opaque{
		Type: RegComplete,
	}
	return returnMessage, nil
}

// ServerAuthenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func ServerAuthenticateInit(o Opaque, server *Server) (Opaque, error) {
	if core.Debug {
		message("debug", "Entering into opaque.ServerAuthenticateInit() function...")
	}

	// 1 - Receive the user's UserAuthInit
	server.Kex = gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	server.auth = gopaque.NewServerAuth(gopaque.CryptoDefault, server.Kex)

	var userInit gopaque.UserAuthInit
	errFromBytes := userInit.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errFromBytes != nil {
		return Opaque{}, fmt.Errorf("there was an error unmarshalling the user init message from bytes:\r\n%s", errFromBytes)
	}

	serverAuthComplete, errServerAuthComplete := server.auth.Complete(&userInit, server.regComplete)

	if errServerAuthComplete != nil {
		return Opaque{}, fmt.Errorf("there was an error completing the OPAQUE server authentication:\r\n%s", errServerAuthComplete.Error())
	}

	if core.Debug {
		message("debug", fmt.Sprintf("User Auth Init:\r\n%+v", userInit))
		message("debug", fmt.Sprintf("Server Auth Complete:\r\n%+v", serverAuthComplete))
	}

	serverAuthCompleteBytes, errServerAuthCompleteBytes := serverAuthComplete.ToBytes()
	if errServerAuthCompleteBytes != nil {
		return Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE server authentication complete message to bytes:\r\n%s", errServerAuthCompleteBytes.Error())
	}

	returnMessage := Opaque{
		Type:    AuthInit,
		Payload: serverAuthCompleteBytes,
	}

	return returnMessage, nil
}

// ServerAuthenticateComplete consumes the Agent's authentication messages and finishes the authentication and key exchange
func ServerAuthenticateComplete(o Opaque, server *Server) error {
	if core.Debug {
		message("debug", "Entering into opaque.ServerAuthenticateComplete() function")
	}

	var userComplete gopaque.UserAuthComplete
	errFromBytes := userComplete.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errFromBytes != nil {
		return fmt.Errorf("there was an error unmarshalling the user complete message from bytes:\r\n%s", errFromBytes)
	}

	// server auth finish
	errAuthFinish := server.auth.Finish(&userComplete)
	if errAuthFinish != nil {
		return fmt.Errorf("there was an error finishing authentication:\r\n%s", errAuthFinish)
	}

	return nil
}

// UserRegisterInit is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration steps for the user
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

// UserRegisterComplete consumes the Server's response and finishes OPAQUE registration
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

// UserAuthenticateComplete consumes the Server's authentication message and finishes the user authentication and key exchange
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
