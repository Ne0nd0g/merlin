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

package opaque

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin-message/opaque"

	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
)

// TestAuthenticateCompleteRejectsBadProof is the regression test for finding S1 of
// GHSA-j4v3-8vg5-7p7g. authenticateComplete() must verify the OPAQUE proof before it
// marks the agent authenticated/alive. Previously the flags were set first and never
// rolled back, so a bogus AuthComplete left the agent flagged authenticated.
func TestAuthenticateCompleteRejectsBadProof(t *testing.T) {
	// Agents create a ./data log directory relative to the working directory; run
	// from a temp dir so the test does not litter the repo.
	t.Chdir(t.TempDir())

	auth, err := NewAuthenticator()
	if err != nil {
		t.Fatalf("could not create authenticator: %s", err)
	}

	// NewAgentService returns the package singleton the authenticator also uses, so
	// an agent added here is visible to authenticateComplete.
	as := agent.NewAgentService()
	id := uuid.New()
	a, err := agents.NewAgent(id, []byte("test"), nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("could not create agent: %s", err)
	}
	if err = as.Add(a); err != nil {
		t.Fatalf("could not add agent: %s", err)
	}

	// A syntactically invalid proof: ServerAuthenticateComplete fails to unmarshal it
	// and returns an error, exactly as a rogue AuthComplete would.
	badMsg := opaque.Opaque{Type: opaque.AuthComplete, Payload: []byte("not-a-valid-opaque-proof")}
	if err = auth.authenticateComplete(id, badMsg); err == nil {
		t.Fatal("authenticateComplete accepted an invalid OPAQUE proof; expected an error")
	}

	// The agent must NOT have been marked authenticated or alive by a failed proof.
	if as.Authenticated(id) {
		t.Error("agent was marked authenticated despite a failed OPAQUE proof (S1 regression)")
	}
	got, err := as.Agent(id)
	if err != nil {
		t.Fatalf("could not fetch agent: %s", err)
	}
	if got.Alive() {
		t.Error("agent was marked alive despite a failed OPAQUE proof (S1 regression)")
	}
}
