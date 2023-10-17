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
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

/* RPC FUNCTIONS TO INTERACT WITH LISTENERS */

// CreateListener instantiates a listener on the RPC server from the provided options
func CreateListener(options map[string]string) (msg *message.UserMessage) {
	response, err := service.merlinClient.CreateListener(context.Background(), &pb.Options{Options: options})
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error calling the CreateListener RPC method: %s", err))
		return
	}
	msg = newUserMessageFromPBMessage(response)
	return
}

// ListenerGetConfiguredOptions returns a map of the Listener's configured options
func ListenerGetConfiguredOptions(id uuid.UUID) (msg *message.UserMessage, options map[string]string) {
	o, err := service.merlinClient.GetListenerOptions(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetListenerConfiguredOptions RPC method: %s", err)
		slog.Error(err.Error())
		return message.NewErrorMessage(err), nil
	}
	options = o.Options
	msg = message.NewUserMessage(message.Success, "Listener options retrieved successfully")
	return
}

// ListenerGetDefaultOptions returns a map of the Listener's default options
func ListenerGetDefaultOptions(listenerType string) (msg *message.UserMessage, options map[string]string) {
	o, err := service.merlinClient.GetListenerDefaultOptions(context.Background(), &pb.String{Data: listenerType})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetListenerDefaultOptions RPC method: %s", err)
		slog.Error(err.Error())
		return message.NewErrorMessage(err), nil
	}
	options = o.Options
	msg = message.NewUserMessage(message.Success, fmt.Sprintf("Successfully retrieved default options for the '%s' listener", listenerType))
	return
}

// ListenerGetTypes returns a list of all available Listener types (e.g. http, tcp, etc.)
func ListenerGetTypes() (msg *message.UserMessage, types []string) {
	t, err := service.merlinClient.GetListenerTypes(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetListenerTypes RPC method: %s", err)
		slog.Error(err.Error())
		return message.NewErrorMessage(err), nil
	}
	types = t.Data
	msg = message.NewUserMessage(message.Success, "Successfully retrieved listener types")
	return
}

// ListenerGetRows gets information about all configured listeners as data that can be used to populate a table
func ListenerGetRows() (msg *message.UserMessage, header []string, rows [][]string) {
	tableData, err := service.merlinClient.GetListeners(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetListenerRows RPC method: %s", err)
		slog.Error(err.Error())
		return message.NewErrorMessage(err), nil, nil
	}
	msg = message.NewUserMessage(message.Success, "Successfully retrieved listener rows")

	header = tableData.Header
	// Convert the TableRows to a [][]string
	for _, row := range tableData.Rows {
		rows = append(rows, row.Row)
	}
	return
}

// ListenerGetIDs retrieves a list of all instantiated listener IDs from the RPC server
func ListenerGetIDs() (msg *message.UserMessage, ids []string) {
	response, err := service.merlinClient.GetListenerIDs(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetListenerIDs RPC method: %s", err)
		slog.Error(err.Error())
		return message.NewErrorMessage(err), nil
	}
	ids = response.Data
	msg = message.NewUserMessage(message.Success, "Successfully retrieved listener IDs")
	return
}

// ListenerSetOption saves a configurable listener option in the server database
func ListenerSetOption(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.SetListenerOption(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// ListenerStop terminates the Listener's server
func ListenerStop(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.StopListener(context.Background(), &pb.ID{Id: id.String()}))
}

// ListenerStatus returns the status of the Listener's server
func ListenerStatus(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.GetListenerStatus(context.Background(), &pb.ID{Id: id.String()}))
}

// RemoveListener deletes a listener from the server
func RemoveListener(id uuid.UUID) (msg *message.UserMessage) {
	response, err := service.merlinClient.RemoveListener(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error calling the RemoveListener RPC method: %s", err))
		return
	}
	msg = newUserMessageFromPBMessage(response)
	return
}

// RestartListener restarts a listener on the server
func RestartListener(id uuid.UUID) (msg *message.UserMessage) {
	response, err := service.merlinClient.RestartListener(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error calling the RestartListener RPC method: %s", err))
		return
	}
	msg = newUserMessageFromPBMessage(response)
	return
}

// Servers return a list of listeners' type that is available on the server
// Some listeners (e.g., HTTPS) have a server while others (e.g., SMB) do not
func Servers() []string {
	data, err := service.merlinClient.Servers(context.Background(), &emptypb.Empty{})
	if err != nil {
		msg := message.NewErrorMessage(fmt.Errorf("there was an error calling the Servers RPC method: %s", err))
		service.messageRepo.Add(msg)
		return nil
	}
	return data.Data
}

// StartListener start the listener on the RPC server
func StartListener(id uuid.UUID) (msg *message.UserMessage) {
	response, err := service.merlinClient.StartListener(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		return message.NewErrorMessage(fmt.Errorf("there was an error calling the StartListener RPC method: %s", err))
	}
	msg = newUserMessageFromPBMessage(response)
	return
}
