/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2020  Russel Van Tuyl

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

// Additional licenses for external programs and code libraries are at the end of the file
// Moved to the end of the file because it was generating IDE errors with that many lines of comment
package sharpgen

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"os"
	"os/exec"
	"path"
	"strings"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {

	// Check to make sure enough arguments were received
	if len(options) != 13 {
		return nil, fmt.Errorf("14 arguments were expected, %d were provided", len(options))
	}

	// Verify the expected options are present
	opts := []string{"dotnetbin", "sharpgenbin", "help", "file", "dotnet", "output-kind", "platform", "no-optimization", "assembly-name", "source-file", "class-name", "confuse", "code"}

	for _, opt := range opts {
		if _, ok := options[opt]; !ok {
			return nil, fmt.Errorf("the %s option was not found but is required", opt)
		}
	}

	// Check 'dotnetbin' argument first
	_, errStat := os.Stat(options["dotnetbin"])
	// Make sure it exists
	if os.IsNotExist(errStat) {
		// Check to see if it is in the PATH
		_, errDotNet := exec.LookPath(options["dotnetbin"])
		if errDotNet != nil {
			return nil, fmt.Errorf("unable to find dotnet core executable %s\r\nVisit https://dotnet.microsoft.com/download", options["dotnetbin"])
		}
	}

	// Check that the SharpGen binary exists
	// TODO Build SharpGen binary if it isn't there
	if path.IsAbs(options["sharpgenbin"]) {
		s, errA := os.Stat(options["sharpgenbin"])
		if os.IsExist(errA) {
			return nil, fmt.Errorf("the provided absoultue filepath does not exist: %s\r\n%s\r\nBuild SharpGen from it's source directory with: dotnet build -c release", options["sharpgenbin"], errA)
		}
		// Check file permissions
		if s.Mode()&0111 == 0 {
			return nil, fmt.Errorf("the %s file does not have execute permissions: %s", options["sharpgenbin"], s.Mode().Perm())
		}
	} else {
		dll := core.CurrentDir
		s, errDLL := os.Stat(path.Join(dll, options["sharpgenbin"]))
		if os.IsNotExist(errDLL) {
			return nil, fmt.Errorf("unable to find SharpGen executable %s\r\n%s\r\nBuild SharpGen from it's source directory with: dotnet build -c release", options["sharpgenbin"], errDLL)
		}
		// Check file permissions
		if s.Mode()&0111 == 0 {
			return nil, fmt.Errorf("the %s file does not have execute permissions: %s", options["sharpgenbin"], s.Mode().Perm())
		}
	}

	// Parse options for set arguments
	args := []string{options["sharpgenbin"]}

	// Help flag
	if strings.ToLower(options["help"]) == "true" {
		args = append(args, "--help")
	}

	// Output file flag
	args = append(args, "--file", options["file"])

	// dotnet version; If blank use the default
	if options["dotnet"] != "" {
		args = append(args, "--dotnet-framework", options["dotnet"])
	}

	// OutputKind
	if options["output-kind"] != "" {
		args = append(args, "--output-kind", options["output-kind"])
	}

	// Platform
	if options["platform"] != "" {
		args = append(args, "--platform", options["platform"])
	}

	// No Optimization
	if options["no-optimization"] != "" {
		args = append(args, "--no-optimization", options["no-optimization"])
	}

	// Assembly Name
	if options["assembly-name"] != "" {
		args = append(args, "--assembly-name", options["assembly-name"])
	}

	// Source File
	if options["source-file"] != "" {
		// Check to make sure the file is there
		if _, errSource := os.Stat(options["source-file"]); os.IsNotExist(errSource) {
			return nil, fmt.Errorf("unable to find source-file: %s\r\n%s", options["source-file"], errSource)
		}
		args = append(args, "--source-file", options["source-file"])
	}

	// Class Name
	if options["class-name"] != "" {
		args = append(args, "--class-name", options["class-name"])
	}

	// ConfuserEx project file
	if options["confuse"] != "" {
		// Check to make sure the file is there
		if _, errConfuse := os.Stat(options["confuse"]); os.IsNotExist(errConfuse) {
			return nil, fmt.Errorf("unable to find ConfuserEx ProjectFile: %s\r\n%s", options["confuse"], errConfuse)
		}
		args = append(args, "--confuse", options["confuse"])
	}

	// Inline code; This is a positional argument
	if (options["code"] != "") && (options["source-file"] == "") {
		args = append(args, options["code"])
	}

	// Execute SharpGen
	cmd := exec.Command(options["dotnetbin"], args...)
	// TODO Need to send back a messages.UserMessage
	if core.Verbose {
		fmt.Println(cmd.String())
	}
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("there was an error executing SharpGen: %s", err)
	}
	// TODO Need to send back a messages.UserMessage
	if core.Verbose {
		fmt.Println(fmt.Sprintf("%s", stdoutStderr))
	}

	return nil, nil
}
