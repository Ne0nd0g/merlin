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

package util

import (
	// Standard
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	// 3rd Party
	"github.com/fatih/color"
	uuid "github.com/satori/go.uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// GetJWT returns a JSON Web Token for the provided agent using the interface JWT Key
func GetJWT(agentID uuid.UUID, key []byte) (string, error) {
	if core.Debug {
		message("debug", "Entering into agents.GetJWT function")
	}

	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWE encryptor:\r\n%s", encErr)
	}

	signer, errSigner := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if errSigner != nil {
		return "", fmt.Errorf("there was an error creating the JWT signer:\r\n%s", errSigner.Error())
	}

	lifetime, errLifetime := agents.GetLifetime(agentID)
	if errLifetime != nil && errLifetime.Error() != "agent WaitTime is equal to zero" {
		return "", errLifetime
	}

	// This is for when the server hasn't received an AgentInfo struct and doesn't know the agent's lifetime yet or sleep is set to zero
	if lifetime == 0 {
		lifetime = time.Second * 30
	}

	// TODO Add in the rest of the JWT claim info
	cl := jwt.Claims{
		ID:        agentID.String(),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(lifetime)),
	}

	agentJWT, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("there was an error serializing the JWT:\r\n%s", err.Error())
	}

	// Parse it to check for errors
	_, errParse := jwt.ParseEncrypted(agentJWT)
	if errParse != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWT:\r\n%s", errParse.Error())
	}
	logging.Server(fmt.Sprintf("Created authenticated JWT for %s", agentID))
	if core.Debug {
		message("debug", fmt.Sprintf("Sending agent %s an authenticated JWT with a lifetime of %v:\r\n%v",
			agentID.String(), lifetime, agentJWT))
	}

	return agentJWT, nil
}

// ValidateJWT validates the provided JSON Web Token
func ValidateJWT(agentJWT string, key []byte) (uuid.UUID, error) {
	var agentID uuid.UUID
	if core.Debug {
		message("debug", "Entering into jwt.ValidateJWT")
		message("debug", fmt.Sprintf("Input JWT: %v", agentJWT))
	}

	claims := jwt.Claims{}

	// Parse to make sure it is a valid JWT
	nestedToken, err := jwt.ParseSignedAndEncrypted(agentJWT)
	if err != nil {
		return agentID, fmt.Errorf("there was an error parsing the JWT:\r\n%s", err.Error())
	}

	// Decrypt JWT
	token, errToken := nestedToken.Decrypt(key)
	if errToken != nil {
		return agentID, fmt.Errorf("there was an error decrypting the JWT:\r\n%s", errToken.Error())
	}

	// Deserialize the claims and validate the signature
	errClaims := token.Claims(key, &claims)
	if errClaims != nil {
		return agentID, fmt.Errorf("there was an deserializing the JWT claims:\r\n%s", errClaims.Error())
	}

	agentID = uuid.FromStringOrNil(claims.ID)

	AgentWaitTime, errWait := agents.GetAgentFieldValue(agentID, "WaitTime")
	// An error will be returned during OPAQUE registration & authentication
	if errWait != nil {
		if core.Debug {
			message("debug", fmt.Sprintf("there was an error getting the agent's wait time:\r\n%s", errWait.Error()))
		}
	}
	if core.Debug {
		message("debug", fmt.Sprintf("Agent wait time: %s", AgentWaitTime))
	}
	if AgentWaitTime == "" {
		if core.Verbose {
			message("note", "The returned Agent wait time was empty, using default 60s")
		}
		AgentWaitTime = "60s"
	}

	WaitTime, errParse := time.ParseDuration(AgentWaitTime)
	if errParse != nil {
		return agentID, fmt.Errorf("there was an error parsing the agent's wait time into a duration:\r\n%s", errParse.Error())
	}
	// Validate claims; Default Leeway is 1 minute; Set it to 1x the agent's WaitTime setting
	errValidate := claims.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, WaitTime)

	if errValidate != nil {
		if core.Verbose {
			message("warn", fmt.Sprintf("The JWT claims were not valid for %s", agentID))
			message("note", fmt.Sprintf("Agent Wait Time: %s, Time now: %s", AgentWaitTime, time.Now()))
			message("note", fmt.Sprintf("JWT Claim Expiry: %s", claims.Expiry.Time()))
			message("note", fmt.Sprintf("JWT Claim Issued: %s", claims.IssuedAt.Time()))
		}
		return agentID, errValidate
	}
	if core.Debug {
		message("debug", fmt.Sprintf("agentID: %s", agentID.String()))
		message("debug", "Leaving jwt.ValidateJWT without error")
	}
	// TODO I need to validate other things like token age/expiry
	return agentID, nil
}

// DecryptJWE takes provided JWE string and decrypts it using the per-agent key
func DecryptJWE(jweString string, key []byte) (messages.Base, error) {
	if core.Debug {
		message("debug", "Entering into jwt.DecryptJWE function")
		message("debug", fmt.Sprintf("Input JWE String: %s", jweString))
	}

	var m messages.Base

	// Parse JWE string back into JSONWebEncryption
	jwe, errObject := jose.ParseEncrypted(jweString)
	if errObject != nil {
		return m, fmt.Errorf("there was an error parseing the JWE string into a JSONWebEncryption object:\r\n%s", errObject)
	}

	if core.Debug {
		message("debug", fmt.Sprintf("Parsed JWE:\r\n%+v", jwe))
	}

	// Decrypt the JWE
	jweMessage, errDecrypt := jwe.Decrypt(key)
	if errDecrypt != nil {
		return m, fmt.Errorf("there was an error decrypting the JWE:\r\n%s", errDecrypt.Error())
	}

	// Decode the JWE payload into a messages.Base struct
	errDecode := gob.NewDecoder(bytes.NewReader(jweMessage)).Decode(&m)
	if errDecode != nil {
		return m, fmt.Errorf("there was an error decoding JWE payload message sent by an agent:\r\n%s", errDecode.Error())
	}

	if core.Debug {
		message("debug", "Leaving jwt.DecryptJWE function without error")
		message("debug", fmt.Sprintf("Returning message base: %+v", m))
	}
	return m, nil
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
