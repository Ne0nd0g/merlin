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
	"io/ioutil"
	"strings"
)

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
	if err != nil {
		return nil, err
	}

	s := string(data)
	hexString = s

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

	b, errB := ioutil.ReadFile(filePath) // #nosec G304 Users can include any file from anywhere
	if errB != nil {
		return nil, errB
	}

	h, errH := parseHex([]string{string(b)})
	if errH != nil {
		return h, nil
	}

	return b, nil

}
