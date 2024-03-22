/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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

package donut

import (
	"bytes"
	"encoding/base64"
	"path"

	// Standard
	"fmt"
	"os"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/Binject/go-donut/donut"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	arguments := []string{"arch", "bypass", "class", "domain", "entropy", "format", "method", "name", "output", "parameters", "runtime", "server", "entrypoint", "unicode", "exit", "thread", "compress", "sourcefile", "spawnto", "args", "verbose"}

	for _, argument := range arguments {
		if _, ok := options[argument]; !ok {
			return nil, fmt.Errorf("the donut module expected the \"%s\" options but it was not provided", argument)
		}
	}

	config, err := GetDonutConfig(options)
	if err != nil {
		return nil, err
	}

	donutBuffer, err := BytesFromConfig(options["sourcefile"], config)
	if err != nil {
		return nil, fmt.Errorf("there was an error generatring the donut shellcode:\r\n%s", err)
	}

	donutBytes := donutBuffer.Bytes()
	// Write outfile
	if options["output"] != "" {
		f, err := os.Create(options["output"])
		if err != nil {
			// TODO Move to a CLI API call instead of writing to STDOUT
			fmt.Printf("\r\nthere was an error creating the donut output file:\r\n%s\r\n", err)
		}

		defer func() {
			err = f.Close()
		}()

		_, err = donutBuffer.WriteTo(f)
		if err != nil {
			// TODO Move to a CLI API call instead of writing to STDOUT
			fmt.Printf("\r\nthere was an error writing donut shellcode to a file:\r\n%s\r\n", err)
		} else {
			// TODO Move to a CLI API call instead of writing to STDOUT
			fmt.Printf("\r\nWrote donut file to: %s\r\n", options["output"])
		}
	}

	return []string{"CreateProcess", base64.StdEncoding.EncodeToString(donutBytes), options["spawnto"], options["args"]}, nil
}

// GetDonutConfig parses a map of options and returns a donut config structure
func GetDonutConfig(options map[string]string) (*donut.DonutConfig, error) {
	config := new(donut.DonutConfig)

	// Target architecture for loader : 1=x86, 2=amd64, 3=x86+amd64(default)
	arch, err := strconv.Atoi(options["arch"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut architecture value to an integer:\r\n%s", err)
	}
	switch arch {
	case 1:
		config.Arch = donut.X32
	case 2:
		config.Arch = donut.X64
	case 3:
		config.Arch = donut.X84
	default:
		return nil, fmt.Errorf("invalid donut architecture value: %s", options["arch"])
	}

	// Behavior for bypassing AMSI/WLDP : 1=None, 2=Abort on fail, 3=Continue on fail.(default)
	bypass, err := strconv.Atoi(options["bypass"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut bypass level to an integer:\r\n%s", err)
	}
	switch bypass {
	case 1:
		config.Bypass = 1 // None
	case 2:
		config.Bypass = 2 // Abort on fail
	case 3:
		config.Bypass = 3 // Continue on fail
	default:
		return nil, fmt.Errorf("invalid donut bypass level: %s", options["bypass"])
	}

	// Entropy level. 1=None, 2=Generate random names, 3=Generate random names + use symmetric encryption (default)
	entropy, err := strconv.Atoi(options["entropy"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut entropy level to an integer:\r\n%s", err)
	}
	switch entropy {
	case 1:
		config.Entropy = donut.DONUT_ENTROPY_NONE
	case 2:
		config.Entropy = donut.DONUT_ENTROPY_RANDOM
	case 3:
		config.Entropy = donut.DONUT_ENTROPY_DEFAULT
	default:
		return nil, fmt.Errorf("invalid donut entropy level: %s", options["entropy"])
	}

	// The output format of loader saved to file. 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=Hexadecimal
	format, err := strconv.Atoi(options["format"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut format argument to an integer:\r\n%s", err)
	}
	switch format {
	case 1:
		config.Format = 1 // Binary
	case 2:
		config.Format = 2 // Base64
	case 3:
		config.Format = 3 // C
	case 4:
		config.Format = 4 // Ruby
	case 5:
		config.Format = 5 // Python
	case 6:
		config.Format = 6 // PowerShell
	case 7:
		config.Format = 7 // C#
	case 8:
		config.Format = 8 // Hexadecimal
	default:
		return nil, fmt.Errorf("invalid donut format %s", options["format"])
	}

	// Specifies where Donut should save the loader. Default is "loader.bin" in the current directory
	// Validate output file exists
	if options["output"] != "" {
		d, _ := path.Split(options["output"])
		_, err = os.Stat(d)
		if err != nil {
			return nil, fmt.Errorf("invalid donut output argument:\r\n%s", err)
		}
	}

	// URL for the HTTP server that will host a Donut module
	if options["server"] == "" {
		config.InstType = donut.DONUT_INSTANCE_PIC
	} else {
		config.InstType = donut.DONUT_INSTANCE_URL
		config.URL = options[""]
	}

	// Run the entrypoint of an unmanaged/native EXE as a thread and wait for thread to end
	if options["entrypoint"] != "" {
		config.OEP, err = strconv.ParseUint(options["entrypoint"], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("could not convert donut entrypoint to an unsigned integer:\r\n%s", err)
		}
	}

	// Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)
	if strings.ToLower(options["unicode"]) == "true" {
		config.Unicode = 1
	}

	// Determines how the loader should exit. 1=exit thread, 2=exit process
	exit, err := strconv.Atoi(options["exit"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut exit value to an integer:\r\n%s", err)
	}
	switch exit {
	case 1:
		config.ExitOpt = 1 // Exit thread
	case 2:
		config.ExitOpt = 2 // Exit process
	default:
		return nil, fmt.Errorf("invalid donut exit options: %s", options["exit"])
	}

	// Creates a new thread for the loader and continues execution at the address of host process
	if strings.ToLower(options["thread"]) == "true" {
		config.Thread = 1
	}

	// Pack/Compress file. 1=disable, 2=LZNT1, 3=Xpress, 4=Xpress Huffman.
	compress, err := strconv.Atoi(options["compress"])
	if err != nil {
		return nil, fmt.Errorf("could not convert donut compress enging argument to an integer:\r\n%s", err)
	}
	switch compress {
	case 1:
		config.Compress = 1 // None
	case 2:
		config.Compress = 2 // LZNT1
	case 3:
		config.Compress = 3 // Xpress
	case 4:
		config.Compress = 4 // Xpress Huffman
	default:
		return nil, fmt.Errorf("invalid donut compress argument: %s", options["compress"])
	}

	// Verify the input file exists
	_, err = os.Stat(options["sourcefile"])
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("the input donut input file does not exist: %s\r\n%s", options["sourcefile"], err)
	}

	// Verbose output
	if strings.ToLower(options["verbose"]) == "true" {
		config.Verbose = true
	}

	// No checking required
	config.Class = options["class"]   // Optional class name. (required for .NET DLL) Can also include namespace: e.g namespace.class
	config.Domain = options["domain"] // AppDomain name to create for .NET. If entropy is enabled, one will be generated randomly
	config.Method = options["method"] // Optional method or function for DLL. (a method is required for .NET DLL)
	// NOT ENABLED? // Module name for HTTP staging. If entropy is enabled, this is generated randomly
	config.Parameters = options["parameters"] // Optional parameters/command line inside quotations for DLL method/function or EXE
	config.Runtime = options["runtime"]       // CLR runtime version. MetaHeader used by default or v4.0.30319 if none available

	return config, nil
}

// GetDonutDefaultConfig returns a default DonutConfig structure
func GetDonutDefaultConfig() *donut.DonutConfig {
	return donut.DefaultConfig()
}

// BytesFromConfig takes a donut configuration and a file path to an executable as inputs and returns the donut payload as a bytes buffer
func BytesFromConfig(srcFile string, config *donut.DonutConfig) (*bytes.Buffer, error) {
	if config.InstType == donut.DONUT_INSTANCE_URL {
		if config.URL == "" {
			return nil, fmt.Errorf("a donut URL was not provided: %s", config.URL)
		}
		return donut.ShellcodeFromURL(config.URL, config)
	}
	return donut.ShellcodeFromFile(srcFile, config)
}

// BytesFromString takes a base64 encoded .NET assembly and a donut configuration as inputs and returns the donut payload as a bytes buffer
func BytesFromString(assembly string, config *donut.DonutConfig) (*bytes.Buffer, error) {
	// Base64 decode assembly
	data, err := base64.StdEncoding.DecodeString(assembly)
	if err != nil {
		return nil, fmt.Errorf("there was an error base64 decoding the donut assembly:\n%s", err)
	}
	return donut.ShellcodeFromBytes(bytes.NewBuffer(data), config)
}
