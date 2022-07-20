// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

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

package pwnboard

import (
	// Standard
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/logging"
)

/*
The structure of data being sent to the pwnboard server
*/
type pwnBoard struct {
	IPs  string `json:"ip"`
	Type string `json:"type"`
}

func updatepwnBoard(pwnboardURL string, ip string) {
	//logging.Server("[*] PwnBoard Data starting")
	var url string
	if strings.Contains(pwnboardURL, "http") {
		url = fmt.Sprintf("%s/generic", pwnboardURL)
	} else {
		url = fmt.Sprintf("http://%s/generic", pwnboardURL)
	}

	// Create the struct
	data := pwnBoard{
		IPs:  ip,
		Type: "merlin",
	}

	// Define http client vars
	client := http.Client{
		Timeout: 2 * time.Second,
	}

	// Marshal the data
	sendit, err := json.Marshal(data)
	if err != nil {
		logging.Server(fmt.Sprintf("\n[-] ERROR SENDING POST: %s", err))
		return
	}

	// Send the post to pwnboard
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(sendit))
	if err != nil {
		logging.Server(fmt.Sprintf("[-] ERROR SENDING POST: %s", err))
		return
	}
	//logging.Server("[*] PwnBoard Data away")

	defer resp.Body.Close()
}

// Updateserver is the main thread used to keep pwnboard updated of each agents status
func Updateserver(pwnboardURL string) {
	for {
		//logging.Server("Update pwnboard")
		// Iterate over all registered agents
		for _, v := range agents.GetAgents() {
			// If the agent is not dead we'll tell pwnboard
			status, _ := agents.GetAgentStatus(v)
			if status != "Dead" {
				info, _ := agents.GetAgentInfo(v)
				if len(info) >= 8 {
					// Iterate over the data section looking for the IP field
					for _, data := range info {
						if data[0] == "IP" {
							// Perform string parsing on info [127.0.0.1/8 10.1.30.2/24 172.16.2.9/24] -> "127.0.0.1/8", "10.1.30.2/24", "172.16.2.9/24"
							for _, ip := range strings.Split(data[1], "\n") {
								// Remove subnet substring
								uniqueIP := strings.Split(ip, "/")[0]
								// If the IP is not localhost send it to pwnboard
								// This will catch a lot of non-existnet IPs but pwnboard will only care about the ones it's aware of.
								if uniqueIP != "127.0.0.1" {
									updatepwnBoard(pwnboardURL, uniqueIP)
								}
							}
						}
					}
				}
			}
		}
		time.Sleep(4 * time.Minute)
	}
}
