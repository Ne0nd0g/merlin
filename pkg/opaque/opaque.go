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
	"encoding/gob"
	"fmt"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"
	// Internal"
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
