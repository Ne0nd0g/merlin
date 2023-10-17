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

package rpc

import (
	// Standard
	"context"
	"fmt"
	"log/slog"

	// 3rd Party
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	"github.com/Ne0nd0g/merlin/pkg/cli/module"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

/* RPC FUNCTIONS TO INTERACT WITH MODULES */

// GetModule return information about a specific module from the RPC server so a module object can be created on the client
func GetModule(modulePath string) (msg *message.UserMessage, m *module.Module) {
	response, err := service.merlinClient.GetModule(context.Background(), &pb.String{Data: modulePath})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetModule RPC method: %s", err)
		slog.Error(err.Error())
		msg = message.NewErrorMessage(err)
		return
	}

	var moduleOptions []module.Option
	for _, option := range response.Options {
		moduleOptions = append(moduleOptions, module.Option{
			Name:        option.Name,
			Value:       option.Value,
			Description: option.Description,
			Required:    option.Required,
			Flag:        option.Flag,
		})
	}

	m = module.NewModule(
		response.Name,
		response.Platform,
		response.Arch,
		response.Lang,
		response.Description,
		response.Notes,
		response.Extended,
		response.Priv,
		response.Author,
		response.Credits,
		response.Path,
		response.Commands,
		moduleOptions,
	)
	msg = message.NewUserMessage(message.Success, "Successfully retrieved module")
	return
}

// GetModuleList returns a list of all available modules on the RPC server
func GetModuleList() (msg *message.UserMessage, modules []string) {
	response, err := service.merlinClient.GetModuleList(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetModuleList RPC method: %s", err)
		slog.Error(err.Error())
		msg = message.NewErrorMessage(err)
		return
	}

	modules = response.Data
	msg = message.NewUserMessage(message.Success, "Successfully retrieved module list")
	return
}

// RunModule sends information to the RPC server and executes the module there
func RunModule(m *module.Module) (msgs []*message.UserMessage) {
	mr := pb.ModuleRun{
		Name:     m.String(),
		Agent:    m.Agent(),
		Platform: m.Platform(),
		Extended: m.Extended(),
		Commands: m.Commands(),
	}

	for _, option := range m.Options() {
		mr.Options = append(mr.Options, &pb.ModuleOption{
			Name:        option.Name,
			Value:       option.Value,
			Description: option.Description,
			Required:    option.Required,
			Flag:        option.Flag,
		})
	}

	responses, err := service.merlinClient.RunModule(context.Background(), &mr)
	if err != nil {
		err = fmt.Errorf("there was an error calling the RunModule RPC method: %s", err)
		msgs = append(msgs, message.NewErrorMessage(err))
		return
	}
	for _, response := range responses.Messages {
		msgs = append(msgs, newUserMessageFromPBMessage(response))
	}
	return
}
