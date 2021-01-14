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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// Native executes a golang native command that does not use any executables on the host
func Native(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("Entering into commands.Native() with %+v...", cmd))
	var results jobs.Results

	cli.Message(cli.NOTE, fmt.Sprintf("Executing native command: %s", cmd.Command))

	switch cmd.Command {
	// TODO create a function for each Native Command that returns a string and error and DOES NOT use (a *Agent)
	case "ls":
		listing, err := list(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error executing the 'ls' command:\r\n%s", err.Error())
			break
		}
		results.Stdout = listing
	case "cd":
		err := os.Chdir(cmd.Args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error changing directories when executing the 'cd' command:\r\n%s", err.Error())
		} else {
			path, pathErr := os.Getwd()
			if pathErr != nil {
				results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'cd' command:\r\n%s", pathErr.Error())
			} else {
				results.Stdout = fmt.Sprintf("Changed working directory to %s", path)
			}
		}
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error getting the working directory when executing the 'pwd' command:\r\n%s", err.Error())
		} else {
			results.Stdout = fmt.Sprintf("Current working directory: %s", dir)
		}
	default:
		results.Stderr = fmt.Sprintf("%s is not a valid NativeCMD type", cmd.Command)
	}

	if results.Stderr == "" {
		if results.Stdout != "" {
			cli.Message(cli.SUCCESS, results.Stdout)
		}
	} else {
		cli.Message(cli.WARN, results.Stderr)
	}
	return results
}

// list gets and returns a list of files and directories from the input file path
func list(path string) (string, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for list command function: %s", path))
	cli.Message(cli.SUCCESS, fmt.Sprintf("listing directory contents for: %s", path))

	// Resolve relative path to absolute
	aPath, errPath := filepath.Abs(path)
	if errPath != nil {
		return "", errPath
	}
	files, err := ioutil.ReadDir(aPath)

	if err != nil {
		return "", err
	}

	details := fmt.Sprintf("Directory listing for: %s\r\n\r\n", aPath)

	for _, f := range files {
		perms := f.Mode().String()
		size := strconv.FormatInt(f.Size(), 10)
		modTime := f.ModTime().String()[0:19]
		name := f.Name()
		details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
	}
	return details, nil
}
