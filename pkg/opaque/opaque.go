/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package opaque holds the functions and structures to perform OPAQUE registration and authentication
// https://github.com/cfrg/draft-irtf-cfrg-opaque
package opaque

import (
	// Standard
	"bytes"
	"context"
	"fmt"
	"log/slog"

	// 3rd Party
	"github.com/cretz/gopaque/gopaque"
	"github.com/google/uuid"
	"go.dedis.ch/kyber/v3"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message/opaque"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
)

// Server is the structure that holds information for the various steps of the OPAQUE protocol as the server
type Server struct {
	reg         *gopaque.ServerRegister
	regComplete *gopaque.ServerRegisterComplete
	auth        *gopaque.ServerAuth
	Kex         *gopaque.KeyExchangeSigma
}

// ServerRegisterInit is used to perform the OPAQUE Password Authenticated Key Exchange (PAKE) protocol Registration steps for the server
func ServerRegisterInit(AgentID uuid.UUID, o opaque.Opaque, key kyber.Scalar) (opaque.Opaque, *Server, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function")

	server := Server{
		reg: gopaque.NewServerRegister(gopaque.CryptoDefault, key),
	}

	var userRegInit gopaque.UserRegisterInit

	errUserRegInit := userRegInit.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errUserRegInit != nil {
		return opaque.Opaque{}, &server, fmt.Errorf("there was an error unmarshalling the OPAQUE user register initialization message from bytes:\r\n%s", errUserRegInit)
	}

	agentIDBytes, err := AgentID.MarshalBinary()
	if err != nil {
		return opaque.Opaque{}, &server, fmt.Errorf("there was an error marshalling the AgentID to bytes: %s", err)
	}
	if !bytes.Equal(userRegInit.UserID, agentIDBytes) {
		slog.Debug("OPAQUE Server Registration Init", "OPAQUE UserID", fmt.Sprintf("%X", userRegInit.UserID), "Merlin Message UserID", fmt.Sprintf("%X", agentIDBytes))
		regUUID, _ := uuid.FromBytes(userRegInit.UserID)
		return opaque.Opaque{}, &server, fmt.Errorf("the OPAQUE UserID %s doesn't match the Merlin message ID %s", regUUID, AgentID)
	}

	serverRegInit := server.reg.Init(&userRegInit)

	serverRegInitBytes, errServerRegInitBytes := serverRegInit.ToBytes()
	if errServerRegInitBytes != nil {
		return opaque.Opaque{}, &server, fmt.Errorf("there was an error marshalling the OPAQUE server registration initialization message to bytes:\r\n%s", errServerRegInitBytes)
	}

	returnMessage := opaque.Opaque{
		Type:    opaque.RegInit,
		Payload: serverRegInitBytes,
	}

	return returnMessage, &server, nil
}

// ServerRegisterComplete consumes the User's response and finishes OPAQUE Registration
func ServerRegisterComplete(AgentID uuid.UUID, o opaque.Opaque, server *Server) (opaque.Opaque, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function")

	var userRegComplete gopaque.UserRegisterComplete

	errUserRegComplete := userRegComplete.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errUserRegComplete != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error unmarshalling the OPAQUE user register complete message from bytes:\r\n%s", errUserRegComplete.Error())
	}

	server.regComplete = server.reg.Complete(&userRegComplete)

	agentIDBytes, err := AgentID.MarshalBinary()
	if err != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error marshalling the AgentID to bytes: %s", err)
	}

	// Check to make sure Merlin UserID matches OPAQUE UserID
	if !bytes.Equal(agentIDBytes, server.regComplete.UserID) {
		return opaque.Opaque{}, fmt.Errorf("the OPAQUE UserID: %v doesn't match the Merlin UserID: %v", server.regComplete.UserID, agentIDBytes)
	}

	returnMessage := opaque.Opaque{
		Type: opaque.RegComplete,
	}
	return returnMessage, nil
}

// ServerAuthenticateInit is used to authenticate an agent leveraging the OPAQUE Password Authenticated Key Exchange (PAKE) protocol
func ServerAuthenticateInit(o opaque.Opaque, server *Server) (opaque.Opaque, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function")

	// Ensure the server parameter is not nil
	if server == nil {
		return opaque.Opaque{}, fmt.Errorf("pkg/opaque.ServerAuthenticateInit(): the OPAQUE server parameter was nil")
	}

	// 1 - Receive the user's UserAuthInit
	server.Kex = gopaque.NewKeyExchangeSigma(gopaque.CryptoDefault)
	server.auth = gopaque.NewServerAuth(gopaque.CryptoDefault, server.Kex)

	var userInit gopaque.UserAuthInit
	errFromBytes := userInit.FromBytes(gopaque.CryptoDefault, o.Payload)
	if errFromBytes != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error unmarshalling the user init message from bytes:\r\n%s", errFromBytes)
	}

	serverAuthComplete, errServerAuthComplete := server.auth.Complete(&userInit, server.regComplete)

	if errServerAuthComplete != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error completing the OPAQUE server authentication:\r\n%s", errServerAuthComplete.Error())
	}

	slog.Debug("OPAQUE Server Authentication Complete", "User Auth Init", fmt.Sprintf("%+v", userInit), "Server Auth Complete", fmt.Sprintf("%+v", serverAuthComplete))

	serverAuthCompleteBytes, errServerAuthCompleteBytes := serverAuthComplete.ToBytes()
	if errServerAuthCompleteBytes != nil {
		return opaque.Opaque{}, fmt.Errorf("there was an error marshalling the OPAQUE server authentication complete message to bytes:\r\n%s", errServerAuthCompleteBytes.Error())
	}

	returnMessage := opaque.Opaque{
		Type:    opaque.AuthInit,
		Payload: serverAuthCompleteBytes,
	}

	return returnMessage, nil
}

// ServerAuthenticateComplete consumes the Agent's authentication messages and finishes the authentication and key exchange
func ServerAuthenticateComplete(o opaque.Opaque, server *Server) error {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function")

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
