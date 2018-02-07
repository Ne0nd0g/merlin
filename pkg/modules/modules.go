// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2018  Russel Van Tuyl

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

package modules

import (
	// Standard
	"fmt"
	"io/ioutil"
	"encoding/json"
	"strings"
	"errors"

	// 3rd Party
	"github.com/fatih/color"
)

// Module is a structure containing the base information or template for modules
type Module struct {
	Name     string  	`json:"name"` 	// Name of the module
	Author   []string 	`json:"author"`	// A list of module authors
	Path     []string 	`json:"path"`	// Path to the module (i.e. data/modules/powershell/powerview)
	Platform string 	`json:"platform"`	// Platform the module can run on (i.e. Windows, Linux, Darwin, or ALL)
	Arch     string 	`json:"arch"`	// The Architecture the module can run on (i.e. x86, x64, MIPS, ARM, or ALL)
	Lang     string 	`json:"lang"`	// What language does the module execute in (i.e. PowerShell, Python, or Perl)
	Priv     bool		`json:"privilege"` // Does this module required a priviledged level account like root or SYSTEM?
	Description string 	`json:"description"`	// A description of what the module does
	Notes    string 	`json:"notes"`	// Additional information or notes about the module
	Commands []string 	`json:"commands"`	// A list of commands to be run on the agent
	SourceRemote string `json:"remote"`	// Online or remote source code for a module (i.e. https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)
	SourceLocal	[]string 	`json:"local"`	// The local file path to the script or payload
	Options map[string][]string 	`json:"options"`	// A list of configurable options/arguments for the module
	Powershell interface{} `json:"powershell,omitempty"` // An option json object containing commands and configuration items specific to PowerShell
}

// PowerShell structure is used to describe additional PowerShell features for modules that leverage PowerShell
type Powershell struct {
	DisableAV bool // Disable Windows Real Time "Set-MpPreference -DisableRealtimeMonitoring $true"
	Obfuscation bool // Unimplemented command to obfuscated powershell
	Base64 bool // Base64 encode the powershell command?
}

// Run function returns an array of commands to execute the module on an agent
func (m *Module) Run() []string {
	return m.Commands
}

// ShowOptions function is used to display only a module's configurable options
func (m *Module) ShowOptions(){
	for k, v := range m.Options {
		fmt.Printf("%s:\t\t%s\n",k,v)
	}
}

// ShowInfo function displays all of the information about a module to include items such as authors and options
func (m *Module) ShowInfo(){
	color.Yellow("Module:\r\n\t%s\r\n", m.Name)
	color.Yellow("Platform:\r\n\t%s\\%s\\%s\r\n", m.Platform, m.Arch, m.Lang)
	color.Yellow("Authors:")
	for a := range m.Author {
		color.Yellow("\t%s", m.Author[a])
	}
	color.Yellow("Description:\r\n\t%s", m.Description)
	color.Yellow("Options:")
	for k, v := range m.Options {
		color.Yellow("\t%s:\t\t%s",k,v)
	}
	fmt.Println()
	color.Yellow("Notes: %s", m.Notes)

}

// Create is module function used to instantiate a module object using the provided file path to a module's json file
func Create(modulePath string) (Module, error) {
	var m Module

	// Read in the module's JSON configuration file
	f, err := ioutil.ReadFile(modulePath)
	if err != nil {
		return m, err
	}

	// Unmarshal module's JSON message
	var moduleJSON map[string]*json.RawMessage
	errModule := json.Unmarshal(f, &moduleJSON)
	if errModule != nil {
		return m, errModule
	}

	// Determine all message types
	var keys []string
	for k := range moduleJSON {
		keys = append(keys,k)
	}

	// Validate that module's JSON contains at least the base message
	var containsBase bool
	for i := range keys{
		if keys[i] == "base" {
			containsBase = true
		}
	}

	// Marshal Base message type
	if !containsBase {
		return m, errors.New("the module's definition does not contain the 'BASE' message type")
	} else {
		errJson := json.Unmarshal(*moduleJSON["base"], &m)
		if errJson != nil {
			return m, errJson
		}
	}

	// Check for PowerShell configuration options
	for k := range keys{
		switch keys[k]{
		case "base":
		case "powershell":
			k := marshalMessage(*moduleJSON["powershell"])
			m.Powershell = (*json.RawMessage)(&k)
			var p Powershell
			json.Unmarshal(k, &p)
		}
	}

	_, errValidate := validate(m)
	if errValidate != nil {
		return m, errValidate
	}
	return m, nil
}

// validate function is used to check a module's configuration for errors
func validate(m Module) (bool, error) {

	// Validate Platform
	switch strings.ToUpper(m.Platform) {
	case "WINDOWS":
	case "LINUX":
	case "DARWIN":
	default:
		return false, errors.New("invalid 'platform' value provided in module file")
	}

	// Validate Architecture
	switch strings.ToUpper(m.Arch){
	case "X64":
	case "X32":
	default:
		return false, errors.New("invalid 'arch' value provided in module file")
	}
	return true, nil
}

// marshalMessage is a generic function used to marshal JSON messages
func marshalMessage(m interface{}) []byte {
	k, err := json.Marshal(m)
	if err != nil {
		color.Red("There was an error marshaling the JSON object")
		color.Red(err.Error())
	}
	return k
}