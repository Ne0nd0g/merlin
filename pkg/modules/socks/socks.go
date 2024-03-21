/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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
	// Standard
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	// 3rd Party
	"github.com/google/uuid"

	// Merlin Message
	merlinJob "github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/core"
)

// listeners is a map of single TCP-bound interfaces associated keyed to a specific agent ID
var listeners = sync.Map{}

// connections is a map connections keyed to their own ID. There are multiple connections per listener
var connections = sync.Map{}

// done is a map keyed to a connection ID used to signal the go routine that we are done with the connection
var done = sync.Map{}

// jobsIn is a channel used to queue new or out-of-order jobs that will be sent to the SOCKS client
var jobsIn = make(chan merlinJob.Job, 1000)

// JobsOut is a channel used by the pkg/server/jobs/jobs.go to send data to the Merlin agent
var JobsOut = make(chan merlinJob.Job, 1000)

// socksRoutine is a flag to indicate if the go routine used to read from the channel has been started
// Don't want to start the go routine until SOCKS is in use
var socksRoutine bool

// Connection structure is used to track multiple connections per SOCKS listener
type Connection struct {
	AgentID uuid.UUID
	// Conn is the network connection to/from the SOCKS client used to read/write data
	Conn net.Conn
	// Index is used to track and order data being sent to the SOCKS client
	Index int
}

// Parse is the main entry point for the SOCKS module used to receive commands from operators
func Parse(options map[string]string) ([]string, error) {
	// Verify the expected options are present
	opts := []string{"agent", "command", "port", "interface"}

	for _, opt := range opts {
		if _, ok := options[opt]; !ok {
			return nil, fmt.Errorf("the %s option was not found but is required", opt)
		}
	}

	switch strings.ToLower(options["command"]) {
	case "start":
		// Create the listener
		iface := fmt.Sprintf("%s:%s", options["interface"], options["port"])
		listener, err := net.Listen("tcp", iface)
		if err != nil {
			return nil, fmt.Errorf("there was an error starting the SOCKS tcp listener on %s - %s", iface, err)
		}
		// Convert Agent UUID from string
		agent, err := uuid.Parse(options["agent"])
		if err != nil {
			return nil, fmt.Errorf("there was an error converting the agent UUID from a string in the SOCKS module: %s", err)
		}
		// If this is the first listener, then start the go routine to listen for SOCKS messages from the agent
		if !socksRoutine {
			go processMessage()
			socksRoutine = true
		}

		// Add to the global structure
		listeners.Store(agent, listener)

		// Create map used to signal a channel is done
		done.Store(agent, false)

		// Start the listener
		go start(agent)

		return []string{fmt.Sprintf("Started SOCKS listener for agent %s on %s", agent, iface)}, nil
	case "stop":
		// Convert Agent UUID from string
		agent, err := uuid.Parse(options["agent"])
		if err != nil {
			return nil, fmt.Errorf("there was an error converting the agent UUID from a string in the SOCKS module: %s", err)
		}
		listener, ok := listeners.Load(agent)
		if !ok {
			err = fmt.Errorf("there are no listeners for agent %d", agent)
			return nil, err
		}
		// Signal we are done with the listener for the agent
		done.Store(agent, true)

		err = listener.(net.Listener).Close()
		if err != nil {
			// accept tcp 127.0.0.1:9050: use of closed network connection
			err = fmt.Errorf("there was an error stoping the SOCKS listener for the %s agent: %s", agent, err)
			return nil, err
		}

		// Remove items from the map
		listeners.Delete(agent)
		done.Delete(agent)

		msg := fmt.Sprintf("Successfully stopped SOCKS listener for agent %s on %s", agent, listener.(net.Listener).Addr())
		return []string{msg}, err
	default:
		return nil, fmt.Errorf("%s is not a recognized SOCKS module command", options["command"])
	}
}

// start begins an infinite for loop to accept new connections, assign them a unique ID, and then adds it to a map
func start(agent uuid.UUID) {
	for {
		listener, ok := listeners.Load(agent)
		if !ok {
			slog.Error(fmt.Sprintf("there are no listeners for agent %s", agent))
			break
		}
		// Listen for new connections (blocks)
		conn, err := listener.(net.Listener).Accept()

		// Check to see if we are done with the connection. An error will be forced when the listener is closed
		fin, ok := done.Load(agent)
		if !ok {
			slog.Error(fmt.Sprintf("could not find listener's done map for agent %s", agent))
			break
		}
		if fin.(bool) {
			// We closed the listener outside this go routine and just want to exit
			return
		}
		if err != nil {
			slog.Error(fmt.Sprintf("there was an error accepting a SOCKS connection for agent %s: %s", agent, err))
			break
		}
		id := uuid.New()
		if core.Verbose {
			slog.Info(fmt.Sprintf("Received connection from %s to %s and assigned connection ID %s", conn.RemoteAddr(), conn.LocalAddr(), id))
		}
		connection := &Connection{
			AgentID: agent,
			Conn:    conn,
		}

		connections.Store(id, connection)
		go readSOCKSClient(id)
	}
}

// readSOCKSClient reads data from the SOCKS client through the previously accepted connection to the server
func readSOCKSClient(id uuid.UUID) {
	connection, ok := connections.Load(id)
	if !ok {
		slog.Error(fmt.Sprintf("%s is not a known SOCKS connection ID", id))
		return
	}

	var index int
	jobID := core.RandStringBytesMaskImprSrc(10)
	token := uuid.New()
	for {
		// Create SOCKS payload
		socks := merlinJob.Socks{
			ID:    id,
			Index: index,
		}

		// Read the connection data
		data := make([]byte, 500000)
		n, err := connection.(*Connection).Conn.Read(data)
		if core.Debug {
			slog.Debug(fmt.Sprintf("Read %d bytes from connection ID %s for agent %s with error %s", n, id, connection.(Connection).AgentID, err))
		}

		// If there is data, add it to the message
		if n > 0 {
			socks.Data = data[:n]
		}

		// If there is an error, close the connection
		// Errors can occur when the SOCKS client is abruptly closed or the connection is finished
		if err != nil {
			socks.Close = true
			// EOF is not an error it just means the client closed the connection
			if err != io.EOF {
				slog.Error("there was an error reading from the SOCKS client connection", "ID", id, "Index", socks.Index, "Read Data", n, "Error", err)
			}
		}

		// Create the jobs.Job
		job := merlinJob.Job{
			AgentID: connection.(*Connection).AgentID,
			Type:    merlinJob.SOCKS,
			Payload: socks,
			ID:      jobID,
			Token:   token,
		}
		index++
		// Send the job to the agent
		JobsOut <- job
		// The connection is closed on the client side, exit the go routine
		if socks.Close {
			if err == io.EOF {
				slog.Debug("received EOF from the SOCKS client, closing the connection", "Agent", job.AgentID, "ID", socks.ID)
			}
			err = connection.(*Connection).Conn.Close()
			if err != nil {
				slog.Error("there was an error closing SOCKS client connection", "ID", socks.ID, "Index", socks.Index, "Error", err)
			}
			// Delete the connection from the map
			slog.Debug("deleting SOCKS connection", "Agent", job.AgentID, "ID", socks.ID, "Index", socks.Index, "Data Length", len(socks.Data))
			connections.Delete(socks.ID)
			return
		}
	}
}

// processMessage is an infinite loop reading incoming socks connection data from the agent and sending it to the SOCKS client
func processMessage() {
	for {
		job := <-jobsIn
		agent := job.AgentID
		socks := job.Payload.(merlinJob.Socks)

		// Make sure the connection ID is known
		// The Agent can send back data for a connection that has been closed and deleted by the SOCKS client
		// So drop the job
		conn, ok := connections.Load(socks.ID)
		if !ok {
			slog.Debug("Unknown SOCKS connection", "ID", socks.ID, "Index", socks.Index, "Data Length", len(socks.Data))
			continue
		}

		// Ensure this is the right index
		if conn.(*Connection).Index == socks.Index {
			n, err := conn.(*Connection).Conn.Write(socks.Data)
			conn.(*Connection).Index++
			if err != nil {
				slog.Error("there was an error writing to the SOCKS client", "Agent", agent, "ID", socks.ID, "Index", socks.Index, "Close", socks.Close, "Data Length", len(socks.Data), "Error", err)
				continue
			}
			if core.Debug {
				slog.Debug(fmt.Sprintf("Wrote %d bytes with message index %d to the SOCKS client for agent %s connection ID %s with error %s", n, socks.Index, agent, socks.ID, err))
			}
		} else {
			if core.Debug {
				slog.Debug(fmt.Sprintf("Received job out of order for agent %s connection %s. Expected %d, got %d", agent, socks.ID, conn.(*Connection).Index, socks.Index))
			}
			jobsIn <- job
		}
	}
}

// In is the entrypoint for accepting SOCKS messages that came in from the agent and need to be sent to the SOCKS client
func In(job merlinJob.Job) {
	if core.Debug {
		slog.Debug(fmt.Sprintf("Entered into SOCKS module In() function with: %+v", job))
	}

	socks := job.Payload.(merlinJob.Socks)

	// Make sure the connection ID is known
	_, ok := connections.Load(socks.ID)
	if !ok {
		slog.Debug("Unknown SOCKS connection, dropping SOCKS data", "ID", socks.ID, "Index", socks.Index, "Close", socks.Close, "Data Length", len(socks.Data))
		return
	}

	// Add the job to the channel for further processing
	jobsIn <- job
}

// GetListeners returns a list of tracked listeners and the interface/port they are bound to
func GetListeners() [][]string {
	var l [][]string
	listeners.Range(func(k, v interface{}) bool {
		l = append(
			l,
			[]string{k.(uuid.UUID).String(), v.(net.Listener).Addr().String()},
		)
		return true
	})
	return l
}
