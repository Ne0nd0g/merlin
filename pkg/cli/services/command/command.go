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

// Package command is the service for interacting with Command objects
package command

import (
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/memory"
)

// Service holds references to repositories to manage Agent objects or Group objects
type Service struct {
	commandRepo commands.Repository
}

// memoryService is an in-memory instantiation of the Command service so that it can be used by others
var memoryService *Service

// NewCommandService is a factory to create a Command service to be used by other packages or services
func NewCommandService() *Service {
	if memoryService == nil {
		memoryService = &Service{
			commandRepo: WithMemoryCommandRepository(),
		}
	}
	return memoryService
}

// WithMemoryCommandRepository retrieves an in-memory Command repository interface used to manage Command objects
func WithMemoryCommandRepository() commands.Repository {
	return memory.NewRepository()
}

// Load adds all the commands to the repository
func (s *Service) Load() (err error) {
	var cmds []commands.Command
	cmds = append(cmds, commands.Back())
	cmds = append(cmds, commands.CD())
	cmds = append(cmds, commands.CheckIn())
	cmds = append(cmds, commands.Clear())
	cmds = append(cmds, commands.Connect())

	for _, cmd := range cmds {
		err = s.commandRepo.Add(cmd)
		if err != nil {
			return err
		}
	}
	return
}
