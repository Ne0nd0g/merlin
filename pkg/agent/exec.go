// +build !windows

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
	"errors"
	"fmt"
	"os/exec"

	// 3rd Party
	"github.com/mattn/go-shellwords"
)

// ExecuteCommand is function used to instruct an agent to execute a command on the host operating system
func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}

	cmd = exec.Command(name, argS...) // #nosec G204

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeSelf(shellcode []byte) error {
	shellcode = nil
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	shellcode = nil
	pid = 0
	return errors.New("shellcode execution is not implemented for this operating system")
}

// miniDump is a Windows only module function to dump the memory of the provided process
//lint:ignore SA4009 Function needs to mirror exec_windows.go and inputs must be used
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	tempDir = ""
	process = ""
	inPid = 0
	return mini, errors.New("minidump doesn't work on non-windows hosts")
}
