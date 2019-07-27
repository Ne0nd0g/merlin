// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package agent

import (
	// Standard
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net/http"
	"testing"
	"time"

	// 3rd Party
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
	"github.com/Ne0nd0g/merlin/test/testServer"
)

// TestNewHTTPSAgent ensure the agent.New function returns a HTTP/1.1 agent without error
func TestNewHTTPSAgent(t *testing.T) {
	_, err := New("http/1.1", "https://127.0.0.1:8080", "", "test", "http://127.0.0.1:8081", false, false)

	if err != nil {
		t.Error(err)
	}
}

// TestNewH2Agent ensure the agent.New function returns a HTTP/2 agent without error
func TestNewH2Agent(t *testing.T) {
	_, err := New("h2", "https://127.0.0.1:8080", "", "test", "http://127.0.0.1:8081", false, false)

	if err != nil {
		t.Error(err)
	}
}

// TestNewHQAgent ensure the agent.New function returns a HTTP/3 agent without error
func TestNewHQAgent(t *testing.T) {
	_, err := New("hq", "https://127.0.0.1:8080", "", "test", "http://127.0.0.1:8081", false, false)

	if err != nil {
		t.Error(err)
	}
}

// TestKillDate sends a message with a kill date that has been exceeded
func TestKillDate(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	agent.KillDate = 1560616599

	errRun := agent.Run()
	// TODO the function won't actually return unless there is an error
	if errRun == nil {
		t.Errorf("the agent did not quit when the killdate was exceeded")
	}
}

// TestFailedCheckin test for the agent to exit after the amount of failed checkins exceeds the agent's MaxRetry setting
func TestFailedCheckin(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	agent.FailedCheckin = agent.MaxRetry

	errRun := agent.Run()
	if errRun == nil {
		t.Errorf("the agent did not quit when the maximum number of failed checkin atttempts were reached")
	}
}

// TestInvalidMessageType sends a valid message.Base with an invalid Type string
func TestInvalidMessageType(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	m := messages.Base{
		Version: 1.0,
		ID:      agent.ID,
		Type:    "NotReal",
		Token:   agent.JWT,
	}
	_, errSend := agent.sendMessage("POST", m)
	if errSend == nil {
		t.Error("agent handler processed an invalid message type without returning an error")
	}
}

// TestInvalidMessage sends a structure that is not a valid message.Base
func TestInvalidMessage(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8081", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})

	go testserver.TestServer{}.Start("8081", ended, setup, t)
	//wait until set up
	<-setup

	type testMessage struct {
		Alpha   string
		Number  int64
		Boolean bool
	}

	m := testMessage{
		Alpha:   "TestString",
		Number:  1337,
		Boolean: false,
	}

	// Can't use agent.sendMessage because it only accepts valid message.Base objects

	// Convert messages.Base to gob
	messageBytes := new(bytes.Buffer)
	errGobEncode := gob.NewEncoder(messageBytes).Encode(m)
	if errGobEncode != nil {
		t.Errorf("there was an error gob encoding the message:\r\n%s", errGobEncode.Error())
		return
	}

	// Get JWE
	jweString, errJWE := core.GetJWESymetric(messageBytes.Bytes(), agent.secret)
	if errJWE != nil {
		t.Errorf("there was an error getting the JWE:\r\n%s", errJWE.Error())
		return
	}

	// Encode JWE into gob
	jweBytes := new(bytes.Buffer)
	errJWEBuffer := gob.NewEncoder(jweBytes).Encode(jweString)
	if errJWEBuffer != nil {
		t.Errorf("there was an error gob encoding the JWE:\r\n%s", errJWEBuffer.Error())
		return
	}

	req, reqErr := http.NewRequest("POST", agent.URL, jweBytes)
	if reqErr != nil {
		t.Errorf("there was an error sending the POST request:\r\n%s", reqErr.Error())
		return
	}

	if req != nil {
		req.Header.Set("User-Agent", agent.UserAgent)
		req.Header.Set("Content-Type", "application/octet-stream; charset=utf-8")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", agent.JWT))
	}

	// Send the request
	resp, err := agent.Client.Do(req)
	if err != nil {
		t.Errorf("there was an error with the HTTP client while performing a POST:\r\n%s", err.Error())
		return
	}

	close(ended)

	if resp == nil {
		t.Error("the server did not return a response")
		return
	}

	if resp.StatusCode != 500 {
		t.Error("the merlin server did not return a 500 for an invalid message type")
	}

}

// TestPSK ensure that the agent can't successfully communicate with the server using the wrong PSK
func TestPSK(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}
	agent.WaitTime = 5000 * time.Millisecond
	k := sha256.Sum256([]byte("wrongPassword"))
	agent.secret = k[:]

	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})

	go testserver.TestServer{}.Start("8080", ended, setup, t)
	//wait until set up
	<-setup

	m := messages.Base{
		Version: 1.0,
		ID:      agent.ID,
		Type:    "StatusOk",
		Token:   agent.JWT,
	}

	_, errSend := agent.sendMessage("POST", m)
	if errSend == nil {
		t.Error("Agent successfully sent an encrypted message using the wrong key")
		return
	}

	// Try again with the correct password
	k = sha256.Sum256([]byte("test"))
	agent.secret = k[:]
	_, errSend2 := agent.sendMessage("POST", m)
	if errSend2 != nil {
		t.Error("agent was unable communicate with the server using the PSK")
	}
	close(ended)
}

// TestWrongUUID sends a valid message to an agent using a UUID that is different from the running agent
func TestWrongUUID(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	m := messages.Base{
		Version: 1.0,
		ID:      uuid.NewV4(),
		Type:    "ServerOk",
		Token:   agent.JWT,
	}

	_, errHandler := agent.messageHandler(m)
	if errHandler == nil {
		t.Error("the agent handled a message with a wrong UUID without returning an error")
	}
	if errHandler != nil {
		if errHandler.Error() != "the input message UUID did not match this agent's UUID" {
			t.Error(errHandler)
		}
	}
}

// TestInvalidHTTPTrafficPayload sends a gob encoded string to the server to ensure it handles invalid traffic
func TestInvalidHTTPTrafficPayload(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8080", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
	}

	m := messages.Base{
		Version: 1.0,
		ID:      agent.ID,
		Type:    "BadPayload",
		Token:   agent.JWT,
	}

	_, errHandler := agent.sendMessage("POST", m)
	if errHandler == nil {
		t.Error("the agent handled a message with a wrong UUID without returning an error")
	}
}

// TestAuthentication verifies successful authentication using the correct PSK
func TestAuthentication(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8082", "", "test", "", false, false)

	if err != nil {
		t.Error(err)
		return
	}
	agent.WaitTime = 5000 * time.Millisecond

	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})

	go testserver.TestServer{}.Start("8082", ended, setup, t)
	//wait until set up
	<-setup

	authenticated := agent.initialCheckIn(agent.Client)
	if authenticated == false {
		t.Error("the agent did not successfully authenticate")
	}
	close(ended)
}

// TestBadAuthentication verifies unsuccessful authentication using the wrong PSK
func TestBadAuthentication(t *testing.T) {
	agent, err := New("h2", "https://127.0.0.1:8083", "", "neverGonnaGiveYouUp", "", false, false)

	if err != nil {
		t.Error(err)
		return
	}
	agent.WaitTime = 5000 * time.Millisecond

	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})

	go testserver.TestServer{}.Start("8083", ended, setup, t)
	//wait until set up
	<-setup

	authenticated := agent.initialCheckIn(agent.Client)
	if authenticated != false {
		t.Error("the agent successfully authenticated with the wrong PSK")
	}
	close(ended)
}

// Bad content-type header
// TODO test every function of the message handler
