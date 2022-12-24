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

package http

import (
	// Standard
	"fmt"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
)

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

	// Validate claims; Default Leeway is 1 minute; Set it to 1x the agent's WaitTime setting
	errValidate := claims.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 60*time.Second)

	if errValidate != nil {
		if core.Verbose {
			message("warn", fmt.Sprintf("The JWT claims were not valid for %s", agentID))
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
