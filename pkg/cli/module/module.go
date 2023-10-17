/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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

package module

import (
	uuid "github.com/satori/go.uuid"
)

// Module is a structure containing the base information or template for modules
type Module struct {
	id              uuid.UUID // id the unique identifier for this instance of the module
	agent           string    // agent is the Agent the module will be executed on
	name            string    // name is the name of the module
	extended        bool      // extended is true if the module is an extended module or else it is a "standard" module
	author          []string  // author is a list of module authors
	credits         []string  // A list of people to credit for underlying tool or techniques
	path            []string  // Path to the module (i.e., data/modules/powershell/powerview)
	platform        string    // Platform that the module can run on (i.e., Windows, Linux, Darwin, or ALL)
	arch            string    // The Architecture the module can run on (i.e., x86, x64, MIPS, ARM, or ALL)
	lang            string    // What language does the module execute in (i.e., PowerShell, Python, or Perl)
	priv            bool      // Does this module require a privileged level account like root or SYSTEM?
	description     string    // A description of what the module does
	notes           string    // Additional information or notes about the module
	commands        []string  // A list of commands to be run on the agent
	sourceRemote    string    // Online or remote source code for a module
	sourceLocal     []string  // The local file path to the script or payload
	options         []Option  // A list of configurable options/arguments for the module
	originalOptions []Option  // An original and unmodified list of configurable options/arguments for the module
}

// Option is a structure containing the keys for the object
type Option struct {
	Name        string `json:"name"`        // Name of the option
	Value       string `json:"value"`       // Value of the option
	Required    bool   `json:"required"`    // Is this a required option?
	Flag        string `json:"flag"`        // The command line flag used for the option
	Description string `json:"description"` // A description of the option
}

// NewModule instantiates a module object, assigns a unique identifier, and returns the object
func NewModule(name, platform, arch, lang, description, notes string, extended, priv bool, author, credits, path, commands []string, options []Option) *Module {
	// TODO this is not the right way to make a new copy that doesn't point to the original
	origOptions := make([]Option, len(options))
	origOptions = append(origOptions, options...)
	return &Module{
		id:              uuid.NewV4(),
		agent:           "",
		name:            name,
		extended:        extended,
		author:          author,
		credits:         credits,
		path:            path,
		platform:        platform,
		arch:            arch,
		lang:            lang,
		priv:            priv,
		description:     description,
		notes:           notes,
		commands:        commands,
		sourceRemote:    "",
		sourceLocal:     nil,
		options:         options,
		originalOptions: origOptions,
	}
}

func (m *Module) Agent() string {
	return m.agent
}

func (m *Module) Arch() string {
	return m.arch
}

func (m *Module) Author() []string {
	return m.author
}

func (m *Module) Commands() []string {
	return m.commands
}

func (m *Module) Credits() []string {
	return m.credits
}

func (m *Module) Description() string {
	return m.description
}

func (m *Module) Extended() bool {
	return m.extended
}

// ID returns the unique identifier for this instance of the module
func (m *Module) ID() uuid.UUID {
	return m.id
}

func (m *Module) Lang() string {
	return m.lang
}

func (m *Module) Name() string {
	return m.name
}

func (m *Module) Notes() string {
	return m.notes
}

func (m *Module) Options() []Option {
	return m.options
}

// OptionsMap is used to generate a map containing module option names and values to be used with other functions
func (m *Module) OptionsMap() map[string]string {
	optionsMap := make(map[string]string)
	for _, v := range m.Options() {
		optionsMap[v.Name] = v.Value
	}
	return optionsMap
}

func (m *Module) OriginalOptions() []Option {
	return m.originalOptions
}

func (m *Module) Platform() string {
	return m.platform
}

// String returns the name of the module
func (m *Module) String() string {
	return m.name
}

func (m *Module) UpdateAgent(id string) {
	m.agent = id
}

// UpdateOptions updates the options for the module
func (m *Module) UpdateOptions(options []Option) {
	m.options = options
}
