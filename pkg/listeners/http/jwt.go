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
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
)

// GetJWT returns a JSON Web Token for the provided agent using the interface JWT Key
func GetJWT(agentID uuid.UUID, lifetime time.Duration, key []byte) (string, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "agentID", agentID, "lifetime", lifetime, "key", key)

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
	//logging.Server(fmt.Sprintf("Created authenticated JWT for %s", agentID))
	slog.Debug(fmt.Sprintf("Sending agent %s an authenticated JWT with a lifetime of %v:\r\n%v", agentID.String(), lifetime, agentJWT))
	return agentJWT, nil
}
