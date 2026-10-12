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

package socks

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	merlinJob "github.com/Ne0nd0g/merlin-message/jobs"
)

// TestProcessMessageReorders is the regression test for finding S4 of
// GHSA-j4v3-8vg5-7p7g. Agent SOCKS messages that arrive out of order were requeued
// onto jobsIn and re-read immediately, spinning processMessage at 100% CPU when an
// index never matched. processMessage must instead buffer out-of-order messages and
// deliver them to the SOCKS client in index order.
func TestProcessMessageReorders(t *testing.T) {
	// net.Pipe gives a synchronous connection pair: processMessage writes to
	// serverConn, the test reads what the SOCKS client would have received from
	// clientConn.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	id := uuid.New()
	connections.Store(id, &Connection{
		AgentID: uuid.New(),
		Conn:    serverConn,
		pending: make(map[int]merlinJob.Socks),
	})
	defer connections.Delete(id)

	// Collect the bytes delivered to the SOCKS client, in order.
	got := make(chan byte, 8)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				got <- buf[0]
			}
			if err != nil {
				return
			}
		}
	}()

	// Single consumer, matching the production invariant (one processMessage).
	go processMessage()

	sock := func(index int, b byte) merlinJob.Job {
		return merlinJob.Job{
			AgentID: uuid.New(),
			ID:      uuid.New().String(),
			Type:    merlinJob.SOCKS,
			Payload: merlinJob.Socks{ID: id, Index: index, Data: []byte{b}},
		}
	}

	// Deliver out of order: 2, then 0, then 1.
	jobsIn <- sock(2, 'C')
	jobsIn <- sock(0, 'A')
	jobsIn <- sock(1, 'B')

	// The client must receive them reassembled in order: A, B, C.
	for i, want := range []byte{'A', 'B', 'C'} {
		select {
		case b := <-got:
			if b != want {
				t.Fatalf("message %d: got %q, want %q", i, b, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for message %d (%q); out-of-order reassembly is broken", i, want)
		}
	}
}
