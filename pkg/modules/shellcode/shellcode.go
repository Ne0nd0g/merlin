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

package shellcode

import (
	// Standard
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	if len(options) != 3 {
		return nil, fmt.Errorf("3 arguments were expected, %d were provided", len(options))
	}
	var b64 string

	f, errF := os.Stat(options["shellcode"])
	if errF != nil {
		h, errH := parseHex([]string{options["shellcode"]})
		if errH != nil {
			return nil, errH
		}
		b64 = base64.StdEncoding.EncodeToString(h)
	} else {
		if f.IsDir() {
			return nil, fmt.Errorf("a directory was provided instead of a file: %s", options["shellcode"])
		}
		b, errB := parseShellcodeFile(options["shellcode"])
		if errB != nil {
			return nil, fmt.Errorf("there was an error parsing the shellcode file:\r\n%s", errB.Error())
		}
		b64 = base64.StdEncoding.EncodeToString(b)
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
	switch strings.ToLower(options["method"]) {
	case "self":
	case "remote":
	case "rtlcreateuserthread":
	case "userapc":
	default:
		return nil, fmt.Errorf("invalid shellcode execution method: %s", options["method"])

	}
	command, errCommand := GetJob(options["method"], b64, options["pid"])
	if errCommand != nil {
		return nil, fmt.Errorf("there was an error getting the shellcode job:\r\n%s", errCommand.Error())
	}

	return command, nil
}

// GetJob returns a string array containing the commands, in the proper order, to be used with agents.AddJob
func GetJob(method string, shellcode string, pid string) ([]string, error) {
	// TODO shellcode input needs to be Base64 encoded
	switch strings.ToLower(method) {
	case "self":
		return []string{"shellcode", "self", shellcode}, nil
	case "remote":
		return []string{"shellcode", "remote", pid, shellcode}, nil
	case "rtlcreateuserthread":
		return []string{"shellcode", "rtlcreateuserthread", pid, shellcode}, nil
	case "userapc":
		return []string{"shellcode", "userapc", pid, shellcode}, nil
	}
	return nil, errors.New("a valid shellcode method was not provided")
}

// parseHex evaluates a string array to determine its format and returns a byte array of the hex
func parseHex(str []string) ([]byte, error) {
	hexString := strings.Join(str, "")

	data, err := base64.StdEncoding.DecodeString(hexString)
	if err == nil {
		s := string(data)
		hexString = s
	}

	// see if string is prefixed with 0x
	if hexString[0:2] == "0x" {
		hexString = strings.Replace(hexString, "0x", "", -1)
		if strings.Contains(hexString, ",") {
			hexString = strings.Replace(hexString, ",", "", -1)
		}
		if strings.Contains(hexString, " ") {
			hexString = strings.Replace(hexString, " ", "", -1)
		}
	}

	// see if string is prefixed with \x
	if hexString[0:2] == "\\x" {
		hexString = strings.Replace(hexString, "\\x", "", -1)
		if strings.Contains(hexString, ",") {
			hexString = strings.Replace(hexString, ",", "", -1)
		}
		if strings.Contains(hexString, " ") {
			hexString = strings.Replace(hexString, " ", "", -1)
		}
	}

	h, errH := hex.DecodeString(hexString)

	return h, errH

}

// parseShellcodeFile parses a path, evaluates the file's contents, and returns a byte array of shellcode
func parseShellcodeFile(filePath string) ([]byte, error) {

	fileContents, err := ioutil.ReadFile(filePath) // #nosec G304 Users can include any file from anywhere
	if err != nil {
		return nil, err
	}

	hexBytes, errHex := parseHex([]string{string(fileContents)})

	// If there was an error parsing the bytes then it probably wasn't ASCII hex, therefore continue on
	if errHex == nil {
		return hexBytes, nil
	}

	// See if it is Base64 encoded binary blob
	base64Data, errB64 := base64.StdEncoding.DecodeString(string(fileContents))
	if errB64 == nil {
		return base64Data, nil
	}

	return fileContents, nil
}
