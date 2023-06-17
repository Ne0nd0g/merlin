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

package memory

import (
	"errors"
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/back"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/cd"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"sync"
)

var pkg = "pkg/cli/commands/memory.go"
var ErrCommandExists = errors.New(fmt.Sprintf("%s: command already exists", pkg))
var ErrCommandNotFound = errors.New(fmt.Sprintf("%s: command not found", pkg))
var ErrCommandNotInMenu = errors.New(fmt.Sprintf("%s: command not in menu", pkg))

// Repository structure implements an in-memory database that holds a map of Command structures used with the Merlin CLI
type Repository struct {
	// Don't use pointers because this map is the source and should only be modified here in the repository
	commands map[string]commands.Command
	sync.Mutex
}

// repo is the in-memory database
var repo *Repository

// NewRepository creates and returns a Repository structure that contains an in-memory map of agents
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			commands: make(map[string]commands.Command),
		}
		repo.load()
	}
	return repo
}

func (r *Repository) Add(cmd commands.Command) {
	r.Lock()
	defer r.Unlock()
	r.commands[cmd.String()] = cmd
	return
}

func (r *Repository) Get(m menu.Menu, cmd string) (command commands.Command, err error) {
	r.Lock()
	defer r.Unlock()
	var ok bool
	if command, ok = r.commands[cmd]; ok {
		if command.Menu(m) {
			return
		}
		err = ErrCommandNotInMenu
		return
	}
	err = ErrCommandNotFound
	return
}

func (r *Repository) GetAll() (commands []commands.Command) {
	r.Lock()
	defer r.Unlock()
	for _, cmd := range r.commands {
		commands = append(commands, cmd)
	}
	return
}

func (r *Repository) load() {
	r.Add(agent.NewCommand())
	r.Add(back.NewCommand())
	r.Add(banner.NewCommand())
	r.Add(cd.NewCommand())
}
