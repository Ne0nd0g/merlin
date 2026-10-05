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

	"github.com/Ne0nd0g/merlin-message/opaque"
)

// TestServerAuthenticateCompleteGuards is the regression test for finding S2 of
// GHSA-j4v3-8vg5-7p7g. ServerAuthenticateComplete must return an error, not panic,
// when the server parameter is nil or when its auth state was never initialized by
// ServerAuthenticateInit (an agent sending AuthComplete without a preceding AuthInit).
func TestServerAuthenticateCompleteGuards(t *testing.T) {
	// A nil server must be rejected with an error.
	if err := ServerAuthenticateComplete(opaque.Opaque{}, nil); err == nil {
		t.Error("ServerAuthenticateComplete(nil server) returned nil; expected an error")
	}

	// A server that never ran ServerAuthenticateInit has a nil auth; the previous
	// code dereferenced server.auth and panicked here.
	if err := ServerAuthenticateComplete(opaque.Opaque{Payload: []byte("anything")}, &Server{}); err == nil {
		t.Error("ServerAuthenticateComplete(uninitialized server) returned nil; expected an error")
	}
}
