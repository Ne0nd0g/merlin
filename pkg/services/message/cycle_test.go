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

package message

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/job"
)

// TestDelegateCycleRecursion is the regression test for GHSA-j4v3-8vg5-7p7g. A
// rogue agent could seed a cycle in the peer-to-peer link graph; the server then
// walked that graph with mutually recursive getBase/getDelegates calls that had no
// cycle detection, overflowing the goroutine stack and killing the process with an
// unrecoverable fatal error.
//
// The test builds the minimal two-node cycle A -> B -> A. That shape deliberately
// defeats the self-link/duplicate guard in Agent.AddLink (neither edge is a self
// link), so it exercises the visited-set guard in the graph walk itself. Before the
// fix this crashes the whole test binary with "fatal error: stack overflow"; after
// the fix getBase returns normally.
func TestDelegateCycleRecursion(t *testing.T) {
	// Agents create per-agent log directories under ./data relative to the working
	// directory; run from a temp dir so the test does not litter the repo.
	t.Chdir(t.TempDir())

	as := agent.NewAgentService()
	js := job.NewJobService()

	idA := uuid.New() // "entry point" agent; nobody's child
	idB := uuid.New() // child of A that links back to A

	for _, id := range []uuid.UUID{idA, idB} {
		a, err := agents.NewAgent(id, []byte("test"), nil, time.Now().UTC())
		if err != nil {
			t.Fatalf("could not create agent %s: %s", id, err)
		}
		if err = as.Add(a); err != nil {
			t.Fatalf("could not add agent %s: %s", id, err)
		}
		if err = as.UpdateAuthenticated(id, true); err != nil {
			t.Fatalf("could not authenticate agent %s: %s", id, err)
		}
		if err = as.UpdateAlive(id, true); err != nil {
			t.Fatalf("could not set agent %s alive: %s", id, err)
		}
		// Mute the agent with a negative wait so getBase returns at the "muted"
		// check before reaching Construct(), which needs listener wiring that is
		// unrelated to the cycle bug under test.
		if err = as.UpdateComms(id, agents.Comms{Wait: "-1s"}); err != nil {
			t.Fatalf("could not set agent %s comms: %s", id, err)
		}
		// Add a job so the job service creates the agent's channel; it is drained
		// below so Get returns empty (no error) during the walk.
		if _, err = js.Add(id, "agentInfo", []string{}); err != nil {
			t.Fatalf("could not add a job for agent %s: %s", id, err)
		}
	}

	// Exactly the edges pkg/services/message.delegate() would write from two
	// attacker-chosen delegate messages: A names B as its child, B names A as its
	// child. Together they close a cycle that neither the self-link nor duplicate
	// guard rejects.
	if err := as.Link(idA, idB); err != nil {
		t.Fatalf("could not link A->B: %s", err)
	}
	if err := as.Link(idB, idA); err != nil {
		t.Fatalf("could not link B->A: %s", err)
	}

	s := &Service{
		agentService:  as,
		jobService:    js,
		delegates:     withDelegateMemoryRepository(),
		clientMsgRepo: withClientMessageMemoryRepository(),
	}

	// Drain the queued jobs so jobService.Get returns empty without error during
	// the walk; together with the muted wait that makes getBase return before
	// Construct for both agents.
	if _, err := js.Get(idA); err != nil {
		t.Fatalf("could not drain jobs for A: %s", err)
	}
	if _, err := js.Get(idB); err != nil {
		t.Fatalf("could not drain jobs for B: %s", err)
	}

	// getBase(idA) is what Handle() runs for every authenticated check-in. It must
	// terminate instead of recursing into the A<->B cycle forever.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.getBase(idA)
	}()

	select {
	case <-done:
		// Returned without overflowing the stack: the cycle was detected.
	case <-time.After(10 * time.Second):
		t.Fatal("getBase did not return within 10s; the link-graph walk is not cycle-safe")
	}
}
