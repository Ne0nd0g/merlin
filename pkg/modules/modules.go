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

package modules

import (
	// Standard
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	// Third-Party
	"github.com/google/uuid"
)

// Module is a structure containing the base information or template for modules
type Module struct {
	id              uuid.UUID   // id the unique identifier for this instance of the module
	Agent           uuid.UUID   // The Agent that will later be associated with this module prior to execution
	Name            string      `json:"name"`        // Name of the module
	Type            string      `json:"type"`        // Type of module (i.e., standard or extended)
	Author          []string    `json:"author"`      // A list of module authors
	Credits         []string    `json:"credits"`     // A list of people to credit for underlying tool or techniques
	Path            []string    `json:"path"`        // Path to the module (i.e., data/modules/powershell/powerview)
	Platform        string      `json:"platform"`    // Platform that the module can run on (i.e., Windows, Linux, Darwin, or ALL)
	Arch            string      `json:"arch"`        // The Architecture the module can run on (i.e., x86, x64, MIPS, ARM, or ALL)
	Lang            string      `json:"lang"`        // What language does the module execute in (i.e., PowerShell, Python, or Perl)
	Priv            bool        `json:"privilege"`   // Does this module require a privileged level account like root or SYSTEM?
	Description     string      `json:"description"` // A description of what the module does
	Notes           string      `json:"notes"`       // Additional information or notes about the module
	Commands        []string    `json:"commands"`    // A list of commands to be run on the agent
	SourceRemote    string      `json:"remote"`      // Online or remote source code for a module
	SourceLocal     []string    `json:"local"`       // The local file path to the script or payload
	Options         []Option    `json:"options"`     // A list of configurable options/arguments for the module
	originalOptions []Option    // An original and unmodified list of configurable options/arguments for the module
	Powershell      interface{} `json:"powershell,omitempty"` // An option json object containing commands and configuration items specific to PowerShell
	IsExtended      bool        // Is this an extended module?
}

// Option is a structure containing the keys for the object
type Option struct {
	Name        string `json:"name"`        // Name of the option
	Value       string `json:"value"`       // Value of the option
	Required    bool   `json:"required"`    // Is this a required option?
	Flag        string `json:"flag"`        // The command line flag used for the option
	Description string `json:"description"` // A description of the option
}

// PowerShell structure is used to describe additional PowerShell features for modules that leverage PowerShell
type PowerShell struct {
	DisableAV   bool // Disable Windows Real Time "Set-MpPreference -DisableRealtimeMonitoring $true"
	Obfuscation bool // Unimplemented command to obfuscated powershell
	Base64      bool // Base64 encode the powershell command?
}

// NewModule is a factory to instantiate a module object using the provided file path to a module's json file
func NewModule(modulePath string) (Module, error) {
	m := Module{
		id: uuid.New(),
	}

	// Read in the module's JSON configuration file
	f, err := os.ReadFile(modulePath) // #nosec G304 - User should be able to read in any file
	if err != nil {
		return m, err
	}

	// Unmarshal module's JSON message
	var moduleJSON map[string]*json.RawMessage
	err = json.Unmarshal(f, &moduleJSON)
	if err != nil {
		return m, fmt.Errorf("there was an error unmarshaling the module's JSON file at %s: %s", modulePath, err)
	}

	// Determine all message types
	var keys []string
	for k := range moduleJSON {
		keys = append(keys, k)
	}

	// Validate that module's JSON contains at least the base message
	var containsBase bool
	for i := range keys {
		if keys[i] == "base" {
			containsBase = true
		}
	}

	// Marshal Base message type
	if !containsBase {
		return m, errors.New("the module's definition does not contain the 'BASE' message type")
	}
	err = json.Unmarshal(*moduleJSON["base"], &m)
	if err != nil {
		return m, fmt.Errorf("there was an error unmarshaling the module's JSON file at %s: %s", modulePath, err)
	}

	// Check for PowerShell configuration options
	for k := range keys {
		switch keys[k] {
		case "base":
		case "powershell":
			var powershellJSON []byte
			powershellJSON, err = marshalMessage(*moduleJSON["powershell"])
			if err != nil {
				return m, err
			}
			m.Powershell = (*json.RawMessage)(&powershellJSON)
			var p PowerShell
			err = json.Unmarshal(powershellJSON, &p)
			if err != nil {
				return m, errors.New("there was an error unmarshalling the powershell JSON object")
			}
		}
	}

	err = validateModule(m)
	if err != nil {
		return m, fmt.Errorf("there was an error validating the module's JSON file at %s: %s", modulePath, err)
	}
	m.originalOptions = m.Options
	switch strings.ToLower(m.Type) {
	case "extended":
		m.IsExtended = true
	default:
		m.IsExtended = false
	}
	return m, nil
}

// validateModule function is used to check a module's configuration for errors
func validateModule(m Module) error {
	// Validate Platform
	switch strings.ToUpper(m.Platform) {
	case "WINDOWS":
	case "LINUX":
	case "DARWIN":
	default:
		return errors.New("invalid or missing 'platform' value in the module's JSON file")
	}

	// Validate Architecture
	switch strings.ToUpper(m.Arch) {
	case "X64":
	case "X32":
	default:
		return errors.New("invalid or missing 'arch' value in the module's JSON file")
	}

	// Validate Type
	switch strings.ToUpper(m.Type) {
	case "STANDARD":
	case "EXTENDED":
	default:
		return errors.New("invalid or missing `type` value in the module's JSON file")
	}
	return nil
}

// marshalMessage is a generic function used to marshal JSON messages
func marshalMessage(m interface{}) ([]byte, error) {
	k, err := json.Marshal(m)
	if err != nil {
		err = fmt.Errorf("there was an error marshaling the JSON object type %T: %s", m, err)
	}
	return k, err
}

// GetModuleList generates and returns a list of all modules in Merlin's "module" directory folder. Used with tab completion
func GetModuleList() []string {
	dir, err := os.Getwd()
	if err != nil {
		slog.Error(err.Error())
		return []string{}
	}
	ModuleDir := path.Join(filepath.ToSlash(dir), "data", "modules")
	o := make([]string, 0)

	err = filepath.Walk(ModuleDir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", ModuleDir, err)
			return err
		}
		if strings.HasSuffix(f.Name(), ".json") {
			d := strings.SplitAfter(filepath.ToSlash(path), ModuleDir)
			if len(d) > 0 {
				m := d[1]
				m = strings.TrimLeft(m, "/")
				m = strings.TrimSuffix(m, ".json")
				if !strings.Contains(m, "templates") {
					o = append(o, m)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("error walking the path %q: %v\n", ModuleDir, err)
	}
	return o
}
