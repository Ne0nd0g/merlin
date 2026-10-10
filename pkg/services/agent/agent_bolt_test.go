/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2026 Russel Van Tuyl

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

package agent

import (
	// Standard
	"os"
	"path/filepath"
	"testing"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
)

// TestUseBoltAgentRepository verifies that start-up configuration swaps the shared
// Agent service onto the bbolt-backed repository and that it rejects a second call.
func TestUseBoltAgentRepository(t *testing.T) {
	// Reset the process-wide singleton so the test starts from a clean slate, and
	// restore it afterwards so other tests in the package are unaffected.
	memoryService = nil
	t.Cleanup(func() { memoryService = nil })

	dir := t.TempDir()
	t.Chdir(dir) // agents.NewAgent writes log files under ./data/agents
	path := filepath.Join(dir, "agents.db")

	if err := UseBoltAgentRepository(path); err != nil {
		t.Fatalf("UseBoltAgentRepository(): %s", err)
	}

	// A second call once initialized must be rejected.
	if err := UseBoltAgentRepository(path); err == nil {
		t.Fatal("UseBoltAgentRepository() second call: got nil error, want an error")
	}

	// The shared service should now round-trip an Agent through the bolt repository.
	svc := NewAgentService()
	ag, err := agents.NewAgent(uuid.New(), []byte("k"), nil, time.Now())
	if err != nil {
		t.Fatalf("agents.NewAgent(): %s", err)
	}
	if err = svc.Add(ag); err != nil {
		t.Fatalf("Add(): %s", err)
	}
	if _, err = svc.Agent(ag.ID()); err != nil {
		t.Fatalf("Agent(): %s", err)
	}

	// The database file should have been created on disk.
	if _, err = os.Stat(path); err != nil {
		t.Fatalf("expected database file at %s: %s", path, err)
	}
}
