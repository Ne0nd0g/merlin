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
	"testing"
	"time"

	// 3rd Party
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/test/testServer"
)

func getTestAgent(proto string) Agent {
	//creates a reproducible agent to ensure no jiggery pokery during generation

	a := Agent{
		Platform:     "linux", //runtime.GOOS,
		Architecture: "amd64", //runtime.GOARCH,
		Pid:          1337,    //os.Getpid(),
		Version:      "0.0.0", //merlin.Version,
		WaitTime:     300 * time.Millisecond,
		PaddingMax:   4096,
		MaxRetry:     2,
		Skew:         3000,
		Verbose:      true,
		Debug:        true,
		Proto:        proto,
		UserAgent:    "TEST HARNESS Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36",
	}
	id, err := uuid.FromString("f55b5543-106e-4f9b-8ee3-21185de64aaf")
	if err != nil {
		panic(err)
	}
	a.ID = id

	a.UserName = "testuser" //u.Username
	a.UserGUID = "testguid" //u.Gid

	a.HostName = "testhostname"

	a.Ips = append(a.Ips, "127.0.0.1")

	client, errClient := getClient(a.Proto)
	if errClient == nil {
		a.Client = client
	} else {
		if a.Verbose {
			message("warn", errClient.Error())
		}
	}
	return a
}

func TestInitialh2(t *testing.T) {
	//create a new agent with default params and h2 proto
	a := getTestAgent("h2")
	//create a server for the agent to interact with locally
	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})
	port := "8081"
	go testserver.TestServer{}.Start(port, ended, setup, t)
	//wait until set up
	<-setup
	//~~~~ the above can probably be copied into each test function

	//do the test stuff

	//simulate a.Run()
	server := "https://127.0.0.1:" + port

	// Do initial checkin
	if a.initial {
		t.Error("Agent initialised prematurely")
	} else {
		a.initial = a.initialCheckIn(server, a.Client)
	}

	// Ensure after initial, the status checkin is sensible too
	if a.initial {
		a.statusCheckIn(server, a.Client)
	} else {
		t.Error("Agent not marked checked in correctly")
	}

	//signal to the server the test is over
	close(ended)
	//we assume the initial checkin was successful for this case - so check the attribute
	if !a.initial {
		t.Error("Initial checkin failed")
	}

}

func TestBrokenJson(t *testing.T) {
	//create a new agent with default params and h2 proto
	a := getTestAgent("h2")
	//create a server for the agent to interact with locally
	//signalling chans for start/end of test
	setup := make(chan struct{})
	ended := make(chan struct{})
	port := "8082"
	go testserver.TestServer{}.Start(port, ended, setup, t)
	//wait until set up
	<-setup
	//~~~~ the above can probably be copied into each test function

	a.UserAgent = "BrokenJSON" //signal to the test server to send broken json

	//simulate a.Run()
	server := "https://127.0.0.1:" + port

	// Do initial checkin
	if a.initial {
		t.Error("Agent initialised prematurely")
	} else {
		a.initial = a.initialCheckIn(server, a.Client)
	}

	// Ensure after initial, the status checkin is sensible too
	if a.initial {
		a.statusCheckIn(server, a.Client)
	} else {
		t.Error("Agent not marked checked in correctly")
	}

	//signal to the server the test is over
	close(ended)
	//we assume the initial checkin was successful for this case - so check the attribute
	if !a.initial {
		t.Error("Initial checkin failed")
	}

	if a.FailedCheckin < 1 {
		t.Error("Broken response didn't trigger failed checkin increment")
	}
}
