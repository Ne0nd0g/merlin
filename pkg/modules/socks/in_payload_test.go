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
	"testing"

	"github.com/google/uuid"

	merlinJob "github.com/Ne0nd0g/merlin-message/jobs"
)

// TestInRejectsWrongPayloadType is a regression test for finding S3 of
// GHSA-j4v3-8vg5-7p7g. In() previously asserted job.Payload.(merlinJob.Socks) in the
// single-value form, which panics when an agent sends a SOCKS job whose payload is
// the wrong registered type. It must now log and return instead of panicking.
func TestInRejectsWrongPayloadType(t *testing.T) {
	// A SOCKS job whose payload is a Command, not a Socks. The previous code panicked
	// here; the fix must return cleanly. A panic fails the test.
	In(merlinJob.Job{
		AgentID: uuid.New(),
		ID:      uuid.New().String(),
		Type:    merlinJob.SOCKS,
		Payload: merlinJob.Command{Command: "wrong-type"},
	})
}
