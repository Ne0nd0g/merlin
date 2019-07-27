// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/modules/minidump"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/satori/go.uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
	"github.com/Ne0nd0g/merlin/pkg/modules/srdi"
)

// Module is a structure containing the base information or template for modules
type Module struct {
	Agent        uuid.UUID   // The Agent that will later be associated with this module prior to execution
	Name         string      `json:"name"`                 // Name of the module
	Type         string      `json:"type"`                 // Type of module (i.e. standard or extended)
	Author       []string    `json:"author"`               // A list of module authors
	Credits      []string    `json:"credits"`              // A list of people to credit for underlying tool or techniques
	Path         []string    `json:"path"`                 // Path to the module (i.e. data/modules/powershell/powerview)
	Platform     string      `json:"platform"`             // Platform the module can run on (i.e. Windows, Linux, Darwin, or ALL)
	Arch         string      `json:"arch"`                 // The Architecture the module can run on (i.e. x86, x64, MIPS, ARM, or ALL)
	Lang         string      `json:"lang"`                 // What language does the module execute in (i.e. PowerShell, Python, or Perl)
	Priv         bool        `json:"privilege"`            // Does this module required a privileged level account like root or SYSTEM?
	Description  string      `json:"description"`          // A description of what the module does
	Notes        string      `json:"notes"`                // Additional information or notes about the module
	Commands     []string    `json:"commands"`             // A list of commands to be run on the agent
	SourceRemote string      `json:"remote"`               // Online or remote source code for a module (i.e. https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)
	SourceLocal  []string    `json:"local"`                // The local file path to the script or payload
	Options      []Option    `json:"options"`              // A list of configurable options/arguments for the module
	Powershell   interface{} `json:"powershell,omitempty"` // An option json object containing commands and configuration items specific to PowerShell
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

// Run function returns an array of commands to execute the module on an agent
func (m *Module) Run() ([]string, error) {
	if m.Agent == uuid.FromStringOrNil("00000000-0000-0000-0000-000000000000") {
		return nil, errors.New("agent not set for module")
	}

	platform, platformError := agents.GetAgentFieldValue(m.Agent, "platform")
	if platformError != nil {
		return nil, platformError
	}

	if !strings.EqualFold(m.Platform, platform) {
		return nil, fmt.Errorf("the %s module is only compatible with %s platform. The agent's platform is %s", m.Name, m.Platform, platform)
	}

	// Check every 'required' option to make sure it isn't null
	for _, v := range m.Options {
		if v.Required {
			if v.Value == "" {
				return nil, errors.New(v.Name + " is required")
			}
		}
	}

	if strings.ToLower(m.Type) == "extended" {
		extendedCommand, err := getExtendedCommand(m)
		if err != nil {
			return nil, err
		}
		return extendedCommand, nil
	}

	// Fill in or remove options values
	command := make([]string, len(m.Commands))
	copy(command, m.Commands)

	for _, o := range m.Options {
		for k := len(command) - 1; k >= 0; k-- {
			// Check if an option was set WITHOUT the Flag or Value qualifiers
			if strings.Contains(command[k], "{{"+o.Name+"}}") {
				if o.Value != "" {
					command[k] = strings.Replace(command[k], "{{"+o.Name+"}}", o.Flag+" "+o.Value, -1)
				} else {
					command = append(command[:k], command[k+1:]...)
				}
				// Check if an option was set WITH just the Flag qualifier
			} else if strings.Contains(command[k], "{{"+o.Name+".Flag}}") {
				if strings.ToLower(o.Value) == "true" {
					command[k] = strings.Replace(command[k], "{{"+o.Name+".Flag}}", o.Flag, -1)
				} else {
					command = append(command[:k], command[k+1:]...)
				}
				// Check if an option was set WITH just the Value qualifier
			} else if strings.Contains(command[k], "{{"+o.Name+".Value}}") {
				if o.Value != "" {
					command[k] = strings.Replace(command[k], "{{"+o.Name+".Value}}", o.Value, -1)
				} else {
					command = append(command[:k], command[k+1:]...)
				}
			}
		}
	}
	return command, nil
}

// ShowOptions function is used to display only a module's configurable options
func (m *Module) ShowOptions() {
	color.Cyan(fmt.Sprintf("\r\nAgent: %s\r\n", m.Agent.String()))
	color.Yellow("\r\nModule options(" + m.Name + ")\r\n\r\n")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Value", "Required", "Description"})
	// TODO update the tablewriter to the newest version and use the SetColMinWidth for the Description column
	table.SetBorder(false)
	// TODO add option for agent alias here
	table.Append([]string{"Agent", m.Agent.String(), "true", "Agent on which to run module " + m.Name})
	for _, v := range m.Options {
		table.Append([]string{v.Name, v.Value, strconv.FormatBool(v.Required), v.Description})
	}
	table.Render()
}

// GetOptionsList generates and returns a list of the module's configurable options. Used with tab completion
func (m *Module) GetOptionsList() func(string) []string {
	return func(line string) []string {
		o := make([]string, 0)
		for _, v := range m.Options {
			o = append(o, v.Name)
		}
		return o
	}
}

// GetModuleList generates and returns a list of all modules in Merlin's "module" directory folder. Used with tab completion
func GetModuleList() func(string) []string {
	return func(line string) []string {
		ModuleDir := path.Join(filepath.ToSlash(core.CurrentDir), "data", "modules")
		o := make([]string, 0)

		err := filepath.Walk(ModuleDir, func(path string, f os.FileInfo, err error) error {
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
}

// SetOption is used to change the passed in module option's value. Used when a user is configuring a module
func (m *Module) SetOption(option string, value string) (string, error) {
	// Verify this option exists
	for k, v := range m.Options {
		if option == v.Name {
			m.Options[k].Value = value
			return fmt.Sprintf("%s set to %s", v.Name, m.Options[k].Value), nil
		}
	}
	return "", fmt.Errorf("invalid module option: %s", option)
}

// SetAgent is used to set the agent associated with the module.
func (m *Module) SetAgent(agentUUID string) (string, error) {
	if strings.ToLower(agentUUID) == "all" {
		agentUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	}
	i, err := uuid.FromString(agentUUID)
	if err != nil {
		return "", fmt.Errorf("invalid UUID")
	}
	m.Agent = i
	return fmt.Sprintf("agent set to %s", m.Agent.String()), nil
}

// ShowInfo function displays all of the information about a module to include items such as authors and options
func (m *Module) ShowInfo() {
	color.Yellow("Module:\r\n\t%s\r\n", m.Name)
	color.Yellow("Platform:\r\n\t%s\\%s\\%s\r\n", m.Platform, m.Arch, m.Lang)
	color.Yellow("Module Authors:")
	for a := range m.Author {
		color.Yellow("\t%s", m.Author[a])
	}
	color.Yellow("Credits:")
	for c := range m.Credits {
		color.Yellow("\t%s", m.Credits[c])
	}
	color.Yellow("Description:\r\n\t%s", m.Description)
	m.ShowOptions()
	fmt.Println()
	color.Yellow("Notes: %s", m.Notes)
}

// Create is module function used to instantiate a module object using the provided file path to a module's json file
func Create(modulePath string) (Module, error) {
	var m Module

	// Read in the module's JSON configuration file
	f, err := ioutil.ReadFile(modulePath) // #nosec G304 - User should be able to read in any file
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
	errJSON := json.Unmarshal(*moduleJSON["base"], &m)
	if errJSON != nil {
		return m, errJSON
	}

	// Check for PowerShell configuration options
	for k := range keys {
		switch keys[k] {
		case "base":
		case "powershell":
			k := marshalMessage(*moduleJSON["powershell"])
			m.Powershell = (*json.RawMessage)(&k)
			var p PowerShell
			err := json.Unmarshal(k, &p)
			if err != nil {
				return m, errors.New("there was an error unmarshaling the powershell JSON object")
			}
		}
	}

	_, errValidate := validateModule(m)
	if errValidate != nil {
		return m, errValidate
	}
	return m, nil
}

// validateModule function is used to check a module's configuration for errors
func validateModule(m Module) (bool, error) {

	// Validate Platform
	switch strings.ToUpper(m.Platform) {
	case "WINDOWS":
	case "LINUX":
	case "DARWIN":
	default:
		return false, errors.New("invalid or missing 'platform' value in the module's JSON file")
	}

	// Validate Architecture
	switch strings.ToUpper(m.Arch) {
	case "X64":
	case "X32":
	default:
		return false, errors.New("invalid or missing 'arch' value in the module's JSON file")
	}

	// Validate Type
	switch strings.ToUpper(m.Type) {
	case "STANDARD":
	case "EXTENDED":
	default:
		return false, errors.New("invalid or missing `type` value in the module's JSON file")
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

// getExtendedCommand processes "extended" modules and returns the associated command by matching the extended module's
// name to a the Parse function of its associated module package
func getExtendedCommand(m *Module) ([]string, error) {
	// TODO document that every extended module must have a parse function as its entry point
	var extendedCommand []string
	var err error
	switch strings.ToLower(m.Name) {
	case "minidump":
		extendedCommand, err = minidump.Parse(m.getMapFromOptions())
	case "shellcodeinjection":
		extendedCommand, err = shellcode.Parse(m.getMapFromOptions())
	case "srdi":
		extendedCommand, err = srdi.Parse(m.getMapFromOptions())
	default:
		return nil, fmt.Errorf("the %s module's extended command function was not found", m.Name)
	}
	return extendedCommand, err
}

// getMapFromOptions is used to generate a map containing module option names and values to be used with other functions
func (m *Module) getMapFromOptions() map[string]string {
	optionsMap := make(map[string]string)

	for _, v := range m.Options {
		optionsMap[v.Name] = v.Value
	}
	return optionsMap
}
