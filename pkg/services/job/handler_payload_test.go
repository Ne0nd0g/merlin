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

package job

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin-message/jobs"

	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
)

// TestHandlerRejectsWrongPayloadType is a regression test for finding S3 of
// GHSA-j4v3-8vg5-7p7g. An agent can send a well-formed job whose gob-decoded Payload
// is the wrong registered type for the job's Type. The handler previously used
// single-value type assertions that panicked on a mismatch; it must now return an
// error instead.
func TestHandlerRejectsWrongPayloadType(t *testing.T) {
	// Agents create a ./data log directory relative to the working directory.
	t.Chdir(t.TempDir())

	as := agent.NewAgentService()
	js := NewJobService()

	id := uuid.New()
	a, err := agents.NewAgent(id, []byte("test"), nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("could not create agent: %s", err)
	}
	if err = as.Add(a); err != nil {
		t.Fatalf("could not add agent: %s", err)
	}

	// Create a real job so a job-info entry (with a valid token) exists for it.
	// AddJobChannel fills in job.ID and job.Token on the pointer it is given.
	realJob := &jobs.Job{Type: jobs.CONTROL, Payload: jobs.Command{Command: "agentInfo"}}
	if _, err = js.AddJobChannel(id, realJob, []string{}); err != nil {
		t.Fatalf("could not add job: %s", err)
	}

	// Build an AGENTINFO job carrying the correct ID/token but a payload of the wrong
	// type (a jobs.Command instead of a messages.AgentInfo).
	badJob := jobs.Job{
		AgentID: id,
		ID:      realJob.ID,
		Token:   realJob.Token,
		Type:    jobs.AGENTINFO,
		Payload: jobs.Command{Command: "wrong-type"},
	}

	if err = js.Handler([]jobs.Job{badJob}); err == nil {
		t.Fatal("Handler accepted a wrong-type payload; expected an error (S3 regression)")
	}
}
