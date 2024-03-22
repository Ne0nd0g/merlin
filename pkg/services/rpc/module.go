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

package rpc

import (
	// Standard
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strings"

	// 3rd Party
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/donut"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/minidump"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/sharpgen"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/shellcode"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/srdi"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/winapi/createprocess"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

/* RPC METHODS TO INTERACT WITH MODULES */

// getExtendedCommand processes "extended" modules and returns the associated command by matching the extended module's
// name to the Parse function of its associated module package
func getExtendedCommand(name string, options map[string]string) ([]string, error) {
	var extendedCommand []string
	var err error
	switch strings.ToLower(name) {
	case "createprocess":
		extendedCommand, err = createprocess.Parse(options)
	case "donut":
		extendedCommand, err = donut.Parse(options)
	case "minidump":
		extendedCommand, err = minidump.Parse(options)
	case "sharpgen":
		extendedCommand, err = sharpgen.Parse(options)
	case "shellcodeinjection":
		extendedCommand, err = shellcode.Parse(options)
	case "srdi":
		extendedCommand, err = srdi.Parse(options)
	default:
		return nil, fmt.Errorf("the %s module's extended command function was not found", name)
	}
	return extendedCommand, err
}

// GetModule returns all the information needed to instantiate a module object on the RPC client from the RPC server
func (s *Server) GetModule(ctx context.Context, in *pb.String) (data *pb.Module, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Get the absolute path to the module
	cwd, err := os.Getwd()
	if err != nil {
		err = fmt.Errorf("there was an error getting the working directory: %s", err)
		slog.Error(err.Error())
		return
	}
	modulePath := path.Join(cwd, "data", "modules", fmt.Sprintf("%s.json", in.Data))

	module, err := modules.NewModule(modulePath)
	if err != nil {
		err = fmt.Errorf("there was an error getting the module: %s", err)
		slog.Error(err.Error())
		return
	}
	var options []*pb.ModuleOption
	for _, option := range module.Options {
		options = append(options, &pb.ModuleOption{
			Name:        option.Name,
			Value:       option.Value,
			Required:    option.Required,
			Flag:        option.Flag,
			Description: option.Description,
		})
	}

	data = &pb.Module{
		Name:         module.Name,
		Extended:     module.IsExtended,
		Author:       module.Author,
		Credits:      module.Credits,
		Path:         module.Path,
		Platform:     module.Platform,
		Arch:         module.Arch,
		Lang:         module.Lang,
		Priv:         module.Priv,
		Description:  module.Description,
		Commands:     module.Commands,
		Notes:        module.Notes,
		SourceRemote: module.SourceRemote,
		SourceLocal:  module.SourceLocal,
		Options:      options,
	}
	return
}

// GetModuleList returns a list of all modules from the RPC server
func (s *Server) GetModuleList(ctx context.Context, e *emptypb.Empty) (data *pb.Slice, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	return &pb.Slice{Data: modules.GetModuleList()}, nil
}

// RunModule executes the provided module
func (s *Server) RunModule(ctx context.Context, m *pb.ModuleRun) (msgs *pb.Messages, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "module run", m)
	msgs = &pb.Messages{}

	// Parse Agent UUID
	agentID, err := uuid.Parse(m.Agent)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", m.Agent, err)
		slog.Error(err.Error())
		return
	}

	// Make sure the UUID isn't nil
	if agentID == uuid.Nil {
		err = fmt.Errorf("the agent ID cannot be 00000000-0000-0000-0000-000000000000")
		slog.Error(err.Error())
		return
	}

	// If the UUID is that Agent broadcast identifier, make sure the module is compatible with every Agent's platform
	if strings.ToLower(agentID.String()) != "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		a, err := s.agentService.Agent(agentID)
		if err != nil {
			err = fmt.Errorf("there was an error getting agent %s: %s", agentID, err)
			slog.Error(err.Error())
			return nil, err
		}
		if !strings.EqualFold(m.Platform, a.Host().Platform) {
			return nil, fmt.Errorf("the %s module is only compatible with %s platform. The agent's platform is %s", m.Name, m.Platform, a.Host().Platform)
		}
	}

	// Check every 'required' option to make sure it isn't null
	for _, v := range m.Options {
		if v.Required {
			if v.Value == "" {
				err = fmt.Errorf("the %s option is required but was empty", v.Name)
				slog.Error(err.Error())
				return
			}
		}
	}

	var command []string
	// If the module is extended, get the command from the module's source code
	// Else, fill in the command with the options provided
	if m.Extended {
		optionsMap := make(map[string]string)
		for _, v := range m.Options {
			optionsMap[v.Name] = v.Value
		}
		command, err = getExtendedCommand(m.Name, optionsMap)
		if err != nil {
			err = fmt.Errorf("there was an error getting the extended command: %s", err)
			slog.Error(err.Error())
			msgs.Messages = append(msgs.Messages, NewPBErrorMessage(err))
			return
		}
	} else {
		// Fill in or remove options values
		command = make([]string, len(m.Commands))
		copy(command, m.Commands)

		for _, o := range m.Options {
			for k := len(command) - 1; k >= 0; k-- {
				reName := regexp.MustCompile(`(?iU)({{2}` + o.Name + `}{2})`)
				reFlag := regexp.MustCompile(`(?iU)({{2}` + o.Name + `.Flag}{2})`)
				reValue := regexp.MustCompile(`(?iU)({{2}` + o.Name + `.Value}{2})`)
				// Check if an option was set WITHOUT the Flag or Value qualifiers
				if reName.MatchString(command[k]) {
					if o.Value != "" {
						command[k] = reName.ReplaceAllString(command[k], o.Flag+" "+o.Value)
					} else {
						command = append(command[:k], command[k+1:]...)
					}
					// Check if an option was set WITH just the Flag qualifier
				} else if reFlag.MatchString(command[k]) {
					if strings.ToLower(o.Value) == "true" {
						command[k] = reFlag.ReplaceAllString(command[k], o.Flag)
					} else {
						command = append(command[:k], command[k+1:]...)
					}
					// Check if an option was set WITH just the Value qualifier
				} else if reValue.MatchString(command[k]) {
					if o.Value != "" {
						command[k] = reValue.ReplaceAllString(command[k], o.Value)
					} else {
						command = append(command[:k], command[k+1:]...)
					}
				}
			}
		}
	}

	// Make sure the command isn't empty after parsing options
	if len(command) <= 0 {
		msgs.Messages = append(msgs.Messages, NewPBWarnMessage(fmt.Sprintf("the %s module did not return a command to task an agent with", m.Name)))
		return
	}

	// Create the job(s)
	if m.Extended {
		var msg *pb.Message
		msg, err = addJob(agentID.String(), command[0], command[1:])
		if err != nil {
			msgs.Messages = append(msgs.Messages, NewPBErrorMessage(err))
		} else {
			msgs.Messages = append(msgs.Messages, msg)
		}
	} else {
		// Standard modules use the `cmd` message type that must be in position 0
		var msg *pb.Message
		msg, err = addJob(agentID.String(), "run", command)
		if err != nil {
			msgs.Messages = append(msgs.Messages, NewPBErrorMessage(err))
		} else {
			msgs.Messages = append(msgs.Messages, msg)
		}
	}
	return
}
