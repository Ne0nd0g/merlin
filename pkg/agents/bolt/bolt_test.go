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

package bolt

import (
	// Standard
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
)

// newTestAgent returns an Agent whose log file is created under the test's
// working directory. Callers must have already switched the working directory to
// a temp dir (via t.Chdir) because agents.NewAgent writes to ./data/agents/<id>.
func newTestAgent(t *testing.T, secret []byte) agents.Agent {
	t.Helper()
	agent, err := agents.NewAgent(uuid.New(), secret, nil, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatalf("agents.NewAgent(): %s", err)
	}
	return agent
}

// newTestRepo creates a Repository backed by a fresh database inside a temp dir
// and switches the working directory there so agent log files stay contained.
func newTestRepo(t *testing.T) (*Repository, string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "agents.db")
	repo, err := NewRepository(path)
	if err != nil {
		t.Fatalf("NewRepository(): %s", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo, path
}

func TestAddGetRemove(t *testing.T) {
	repo, _ := newTestRepo(t)
	agent := newTestAgent(t, []byte("super-secret"))

	if err := repo.Add(agent); err != nil {
		t.Fatalf("Add(): %s", err)
	}

	// Adding the same ID again must fail.
	if err := repo.Add(agent); !errors.Is(err, ErrAgentExists) {
		t.Fatalf("Add() duplicate: got %v, want ErrAgentExists", err)
	}

	if !repo.Exists(agent.ID()) {
		t.Fatal("Exists(): got false, want true")
	}

	got, err := repo.Get(agent.ID())
	if err != nil {
		t.Fatalf("Get(): %s", err)
	}
	if got.ID() != agent.ID() {
		t.Fatalf("Get() ID: got %s, want %s", got.ID(), agent.ID())
	}
	if string(got.Secret()) != "super-secret" {
		t.Fatalf("Get() Secret: got %q, want %q", got.Secret(), "super-secret")
	}

	if err = repo.Remove(agent.ID()); err != nil {
		t.Fatalf("Remove(): %s", err)
	}
	if repo.Exists(agent.ID()) {
		t.Fatal("Exists() after Remove: got true, want false")
	}
	if _, err = repo.Get(agent.ID()); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("Get() after Remove: got %v, want ErrAgentNotFound", err)
	}
}

func TestUpdatesNotFound(t *testing.T) {
	repo, _ := newTestRepo(t)
	missing := uuid.New()

	cases := map[string]func() error{
		"Update":              func() error { a, _ := agents.NewAgent(missing, nil, nil, time.Now()); return repo.Update(a) },
		"UpdateAlive":         func() error { return repo.UpdateAlive(missing, true) },
		"UpdateAuthenticated": func() error { return repo.UpdateAuthenticated(missing, true) },
		"UpdateNote":          func() error { return repo.UpdateNote(missing, "x") },
		"SetSecret":           func() error { return repo.SetSecret(missing, []byte("x")) },
		"AddLinkedAgent":      func() error { return repo.AddLinkedAgent(missing, uuid.New()) },
		"Remove":              func() error { return repo.Remove(missing) },
		"Log":                 func() error { return repo.Log(missing, "x") },
	}
	for name, fn := range cases {
		if err := fn(); !errors.Is(err, ErrAgentNotFound) {
			t.Errorf("%s() on missing agent: got %v, want ErrAgentNotFound", name, err)
		}
	}
}

func TestPartialUpdatesPersisted(t *testing.T) {
	repo, _ := newTestRepo(t)
	agent := newTestAgent(t, nil)
	if err := repo.Add(agent); err != nil {
		t.Fatalf("Add(): %s", err)
	}

	host := agents.Host{Architecture: "x64", Name: "WS01", Platform: "windows", IPs: []string{"10.0.0.5"}}
	comms := agents.Comms{Proto: "h2c", Wait: "30s", Retry: 7, Skew: 3000}
	link := uuid.New()

	if err := repo.UpdateHost(agent.ID(), host); err != nil {
		t.Fatalf("UpdateHost(): %s", err)
	}
	if err := repo.UpdateComms(agent.ID(), comms); err != nil {
		t.Fatalf("UpdateComms(): %s", err)
	}
	if err := repo.UpdateAlive(agent.ID(), true); err != nil {
		t.Fatalf("UpdateAlive(): %s", err)
	}
	if err := repo.AddLinkedAgent(agent.ID(), link); err != nil {
		t.Fatalf("AddLinkedAgent(): %s", err)
	}

	got, err := repo.Get(agent.ID())
	if err != nil {
		t.Fatalf("Get(): %s", err)
	}
	if !reflect.DeepEqual(got.Host(), host) {
		t.Errorf("Host: got %+v, want %+v", got.Host(), host)
	}
	if !reflect.DeepEqual(got.Comms(), comms) {
		t.Errorf("Comms: got %+v, want %+v", got.Comms(), comms)
	}
	if !got.Alive() {
		t.Error("Alive: got false, want true")
	}
	if links := got.Links(); len(links) != 1 || links[0] != link {
		t.Errorf("Links: got %v, want [%s]", links, link)
	}

	// RemoveLinkedAgent should drop it back to empty.
	if err = repo.RemoveLinkedAgent(agent.ID(), link); err != nil {
		t.Fatalf("RemoveLinkedAgent(): %s", err)
	}
	if got, _ = repo.Get(agent.ID()); len(got.Links()) != 0 {
		t.Errorf("Links after remove: got %v, want empty", got.Links())
	}
}

// TestDurabilityAcrossRestart is the whole point of the adapter: state written by
// one Repository instance must be readable by a fresh instance opened on the same
// database file, simulating a server restart.
func TestDurabilityAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "agents.db")

	id := uuid.New()
	initial := time.Now().UTC().Truncate(time.Second)
	host := agents.Host{Architecture: "arm64", Name: "mac01", Platform: "darwin", IPs: []string{"192.168.1.9"}}

	// First "process lifetime": write some state, then close.
	{
		repo, err := NewRepository(path)
		if err != nil {
			t.Fatalf("NewRepository() #1: %s", err)
		}
		agent, err := agents.NewAgent(id, []byte("persisted-key"), nil, initial)
		if err != nil {
			t.Fatalf("agents.NewAgent(): %s", err)
		}
		if err = repo.Add(agent); err != nil {
			t.Fatalf("Add(): %s", err)
		}
		if err = repo.UpdateHost(id, host); err != nil {
			t.Fatalf("UpdateHost(): %s", err)
		}
		if err = repo.UpdateNote(id, "beachhead"); err != nil {
			t.Fatalf("UpdateNote(): %s", err)
		}
		if err = repo.Close(); err != nil {
			t.Fatalf("Close(): %s", err)
		}
	}

	// Second "process lifetime": reopen the same file and verify everything survived.
	repo, err := NewRepository(path)
	if err != nil {
		t.Fatalf("NewRepository() #2: %s", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	got, err := repo.Get(id)
	if err != nil {
		t.Fatalf("Get() after reopen: %s", err)
	}
	if string(got.Secret()) != "persisted-key" {
		t.Errorf("Secret after reopen: got %q, want %q", got.Secret(), "persisted-key")
	}
	if !reflect.DeepEqual(got.Host(), host) {
		t.Errorf("Host after reopen: got %+v, want %+v", got.Host(), host)
	}
	if got.Note() != "beachhead" {
		t.Errorf("Note after reopen: got %q, want %q", got.Note(), "beachhead")
	}
	if !got.Initial().Equal(initial) {
		t.Errorf("Initial after reopen: got %s, want %s", got.Initial(), initial)
	}
	if all := repo.GetAll(); len(all) != 1 {
		t.Errorf("GetAll after reopen: got %d agents, want 1", len(all))
	}
}
