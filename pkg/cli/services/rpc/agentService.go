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
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/agent"
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

/* RPC FUNCTIONS TO INTERACT WITH THE AGENT SERVICE */

// agentFromAgentInfo is a helper function that converts an AgentInfo protobuf message to an Agent entity structure
func agentFromAgentInfo(info *pb.AgentInfo) (a *agent.Agent) {
	build := agent.Build{
		Build:   info.Build.Build,
		Version: info.Build.Version,
	}

	comms := agent.Comms{
		Failed:  info.Comms.Failed,
		JA3:     info.Comms.JA3,
		Wait:    info.Comms.Wait,
		Retry:   info.Comms.Retry,
		Proto:   info.Comms.Protocol,
		Padding: info.Comms.Padding,
		Kill:    info.Comms.KillDate,
		Skew:    info.Comms.Skew,
	}
	host := agent.Host{
		Name:         info.Host.Name,
		Platform:     info.Host.Platform,
		Architecture: info.Host.Architecture,
		IPs:          info.Host.IPs,
	}

	process := agent.Process{
		ID:        info.Process.ID,
		Integrity: info.Process.IntegrityLevel,
		Name:      info.Process.Name,
		UserName:  info.Process.Username,
		UserGUID:  info.Process.UserGUID,
		Domain:    info.Process.Domain,
	}

	a = agent.NewAgent(
		uuid.FromStringOrNil(info.ID),
		info.Alive,
		info.Authenticated,
		build,
		host,
		process,
		comms,
		info.InitialCheckin,
		info.LastCheckin,
		info.Links,
		info.Listener,
		info.Note,
		info.Status,
		info.Groups,
	)
	return
}

// GetAgent returns an Agent structure for the provided Agent UUID
func GetAgent(id uuid.UUID) (a *agent.Agent, err error) {
	response, err := service.merlinClient.GetAgent(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAgent RPC method: %s", err)
		return
	}
	return agentFromAgentInfo(response), nil
}

// GetAgentsRows returns a row of data for every agent that is alive and includes information about it such as
// the Agent's GUID, platform, user, host, transport, and status
func GetAgentsRows() (header []string, rows [][]string, err error) {
	tableData, err := service.merlinClient.GetAgentRows(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAgentRows RPC method: %s", err)
		return
	}
	header = tableData.Header
	// Convert the TableRows to a [][]string
	for _, row := range tableData.Rows {
		rows = append(rows, row.Row)
	}
	return
}

// GetAgents returns a list of existing Agent UUID values
func GetAgents() (agents []uuid.UUID, err error) {
	response, err := service.merlinClient.GetAgents(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAgents RPC method: %s", err)
		return
	}
	for _, id := range response.Data {
		agents = append(agents, uuid.FromStringOrNil(id))
	}
	return
}

// GetAgentLinks returns a list of linked child Agent IDs
func GetAgentLinks(id uuid.UUID) (links []uuid.UUID, err error) {
	response, err := service.merlinClient.GetAgentLinks(context.Background(), &pb.ID{Id: id.String()})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GetAgentLinks RPC method: %s", err)
		return
	}
	for _, link := range response.Data {
		links = append(links, uuid.FromStringOrNil(link))
	}
	return
}

// GroupAdd adds the provided Agent id to the group on the RPC server
func GroupAdd(id uuid.UUID, group string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.GroupAdd(context.Background(), &pb.Group{AgentID: id.String(), Group: group}))
}

// GroupList lists agents that are part of a specific group
// Return an empty slice instead of an error so that way other functions can still complete
func GroupList(group string) (groups []string) {
	response, err := service.merlinClient.GroupList(context.Background(), &pb.ID{Id: group})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GroupList RPC method: %s", err)
		slog.Error(err.Error())
		return
	}
	groups = response.Data
	return
}

// GroupListAll returns a list of all groups and their member's from the RPC server
func GroupListAll() map[string][]string {
	groupMembers, err := service.merlinClient.GroupListAll(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the GroupListAll RPC method: %s", err)
		slog.Error(err.Error())
		return nil
	}
	members := make(map[string][]string)
	for _, group := range groupMembers.Members {
		members[group.Group] = group.Members
	}
	return members
}

// Groups returns a list of existing group names from the server
// Will not return an error so that completers are not blocked but will instead return an empty slice
func Groups() []string {
	groups, err := service.merlinClient.Groups(context.Background(), &emptypb.Empty{})
	if err != nil {
		err = fmt.Errorf("there was an error calling the Groups RPC method: %s", err)
		slog.Error(err.Error())
		return nil
	}
	return groups.Data
}

// GroupRemove deletes the provided Agent id from the group
func GroupRemove(id uuid.UUID, group string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.GroupRemove(context.Background(), &pb.Group{AgentID: id.String(), Group: group}))
}

// Note sets a note on the Agent's Note field
// args[0] = the note to set
func Note(id uuid.UUID, args []string) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Note(context.Background(), &pb.AgentCMD{ID: id.String(), Arguments: args}))
}

// Remove deletes the agent from the server
func Remove(id uuid.UUID) (msg *message.UserMessage) {
	return buildMessage(service.merlinClient.Remove(context.Background(), &pb.ID{Id: id.String()}))
}
