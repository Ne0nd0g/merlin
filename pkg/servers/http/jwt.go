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

package http

import (
	// Standard
	"context"
	"fmt"
	"log/slog"
	"time"

	// 3rd Party
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
)

// ValidateJWT validates the provided JSON Web Token
func ValidateJWT(agentJWT string, leeway time.Duration, key []byte) (agentID uuid.UUID, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "JWT", agentJWT, "Leeway", leeway, "Key", key)
	defer slog.Log(context.Background(), logging.LevelTrace, "exiting the function", "Agent", agentID, "Error", err)

	claims := jwt.Claims{}

	// Parse to make sure it is a valid JWT
	nestedToken, err := jwt.ParseSignedAndEncrypted(agentJWT)
	if err != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an error parsing the JWT: %s", err)
		return
	}

	// Decrypt JWT
	token, errToken := nestedToken.Decrypt(key)
	if errToken != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an error decrypting the JWT: %s", errToken)
		return
	}

	// Deserialize the claims and validate the signature
	errClaims := token.Claims(key, &claims)
	if errClaims != nil {
		err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an deserializing the JWT claims: %s", errClaims)
		return
	}

	agentID, err = uuid.Parse(claims.ID)
	if err != nil {
		return
	}

	// Validate claims if leeway is greater than or equal to 0
	if leeway >= 0 {
		err = claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, leeway)
		if err != nil {
			err = fmt.Errorf("pkg/servers/http.ValidateJWT(): there was an validating the JWT claims with a leeway of %s: %s", leeway, err)
			slog.Warn(fmt.Sprintf("The JWT claims were not valid for %s: %s", agentID, err), "JWT Claim Expiry", claims.Expiry.Time(), "JWT Claim Issued", claims.IssuedAt.Time())
			return
		}
	} else {
		if core.Verbose {
			slog.Info(fmt.Sprintf("JWT leeway is %s and is less than 0, skipping validation for Agent %s", leeway, agentID))
		}
	}
	// TODO I need to validate other things like token age/expiry
	return
}
