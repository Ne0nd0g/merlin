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
	"strings"
	"time"

	// 3rd Party
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/agents"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

/* RPC METHODS TO INTERACT WITH THE AGENT SERVICE */

// agentToAgentInfo converts a server-side Agent structure into a protobuf AgentInfo structure
func (s *Server) agentToAgentInfo(a agents.Agent) *pb.AgentInfo {
	build := &pb.Build{
		Build:   a.Build().Build,
		Version: a.Build().Version,
	}

	host := &pb.Host{
		Architecture: a.Host().Architecture,
		Platform:     a.Host().Platform,
		Name:         a.Host().Name,
		IPs:          a.Host().IPs,
	}

	comms := &pb.Comms{
		Failed:   int32(a.Comms().Failed),
		JA3:      a.Comms().JA3,
		KillDate: a.Comms().Kill,
		Padding:  int32(a.Comms().Padding),
		Protocol: a.Comms().Proto,
		Retry:    int32(a.Comms().Retry),
		Skew:     a.Comms().Skew,
		Wait:     a.Comms().Wait,
	}

	process := &pb.Process{
		ID:             int32(a.Process().ID),
		IntegrityLevel: int32(a.Process().Integrity),
		Name:           a.Process().Name,
		Username:       a.Process().UserName,
		UserGUID:       a.Process().UserGUID,
		Domain:         a.Process().Domain,
	}
	var links []string
	for _, link := range a.Links() {
		links = append(links, link.String())
	}

	status, err := s.agentService.Status(a.ID())
	if err != nil {
		slog.Error(err.Error())
	}

	// Create the AgentInfo structure
	agentInfo := &pb.AgentInfo{
		ID:             a.ID().String(),
		Alive:          a.Alive(),
		Authenticated:  a.Authenticated(),
		Build:          build,
		Host:           host,
		Comms:          comms,
		Process:        process,
		InitialCheckin: a.Initial().Format(time.RFC3339),
		LastCheckin:    a.StatusCheckin().Format(time.RFC3339),
		Listener:       a.Listener().String(),
		Links:          links,
		Note:           a.Note(),
		Status:         status,
		Groups:         s.agentService.Groups(),
	}
	return agentInfo
}

// GetAgent returns Agent configuration information for the provided id
func (s *Server) GetAgent(ctx context.Context, id *pb.ID) (agentInfo *pb.AgentInfo, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	agentInfo = &pb.AgentInfo{}
	// Parse the UUID from the request
	agentID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		return
	}

	// Get the Agent
	a, err := s.agentService.Agent(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting agent %s: %s", agentID, err)
		return
	}
	agentInfo = s.agentToAgentInfo(a)
	return
}

// GetAgentLinks returns a list of linked child Agent IDs
func (s *Server) GetAgentLinks(ctx context.Context, id *pb.ID) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID from the request
	agentID, err := uuid.Parse(id.Id)
	if err != nil {
		return nil, err
	}

	links, err := s.agentService.Links(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting the links for Agent %s: %s", agentID, err)
		slog.Error(err.Error())
		return nil, err
	}

	var linkIDs []string
	for _, link := range links {
		linkIDs = append(linkIDs, link.String())
	}
	return &pb.Slice{Data: linkIDs}, nil
}

// GetAgentRows returns certain pieces of information for all Agents that can later be displayed in a table on the client
func (s *Server) GetAgentRows(ctx context.Context, e *emptypb.Empty) (*pb.TableData, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	data := &pb.TableData{}
	data.Header = []string{"Agent GUID", "Transport", "Platform", "Host", "User", "Process", "Status", "Last Checkin", "Note"}
	var rows []*pb.TableRows
	for _, a := range s.agentService.Agents() {
		if a.Alive() {
			status, err := s.GetAgentStatus(context.TODO(), &pb.ID{Id: a.ID().String()})
			if err != nil {
				return nil, err
			}

			lastTime := lastCheckin(a.StatusCheckin())

			// Get the process name, sans full path
			var proc string
			if a.Host().Platform == "windows" {
				proc = a.Process().Name[strings.LastIndex(a.Process().Name, "\\")+1:]
			} else {
				proc = a.Process().Name[strings.LastIndex(a.Process().Name, "/")+1:]
			}
			p := fmt.Sprintf("%s(%d)", proc, a.Process().ID)

			row := []string{
				a.ID().String(),
				a.Comms().Proto,
				a.Host().Platform + "/" + a.Host().Architecture,
				a.Host().Name,
				a.Process().UserName,
				p,
				status.Message,
				lastTime,
				a.Note(),
			}
			rows = append(rows, &pb.TableRows{Row: row})
		}
	}
	data.Rows = rows
	return data, nil
}

// GetAgents returns a list of existing Agent UUID values
func (s *Server) GetAgents(ctx context.Context, e *emptypb.Empty) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	var agentIDs []string
	for _, a := range s.agentService.Agents() {
		if a.Alive() {
			agentIDs = append(agentIDs, a.ID().String())
		}
	}
	return &pb.Slice{Data: agentIDs}, nil
}

// GetAgentStatus returns the status of an Agent (e.g., alive, dead, or delayed)
func (s *Server) GetAgentStatus(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		return
	}

	a, err := s.agentService.Agent(agentID)
	if err != nil {
		err = fmt.Errorf("there was an error getting agent %s: %s", agentID, err)
		return
	}
	comms := a.Comms()
	dur, errDur := time.ParseDuration(comms.Wait)
	if errDur != nil && comms.Wait != "" {
		err = fmt.Errorf(fmt.Sprintf("Error converting %s to a time duration: %s", comms.Wait, errDur))
		return
	}
	if comms.Wait == "" {
		msg.Message = "Init"
	} else if a.StatusCheckin().Add(dur).After(time.Now()) {
		msg.Message = "Active"
	} else if a.StatusCheckin().Add(dur * time.Duration(comms.Retry+1)).After(time.Now()) { // +1 to account for skew
		msg.Message = "Delayed"
	} else {
		msg.Message = "Dead"
	}
	return
}

// GroupAdd adds an Agent to the provided group
func (s *Server) GroupAdd(ctx context.Context, in *pb.Group) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentUUID, err := uuid.Parse(in.AgentID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.AgentID, err)
		slog.Error(err.Error())
		return
	}

	err = s.agentService.AddAgentToGroup(in.Group, agentUUID)
	if err != nil {
		err = fmt.Errorf("there was an error adding agent %s to group %s: %s", agentUUID, in.Group, err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Agent %s added to group %s", in.AgentID, in.Group))
	return
}

// GroupList lists Agents that are part of a specific group
// id.Id contains the group name as a string
func (s *Server) GroupList(ctx context.Context, id *pb.ID) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	out := &pb.Slice{}
	if _, ok := s.agentService.GroupMembers()[id.Id]; ok {
		for _, member := range s.agentService.GroupMembers()[id.Id] {
			out.Data = append(out.Data, member.String())
		}
	}
	return out, nil
}

// GroupListAll returns all existing Agent groups and their members
func (s *Server) GroupListAll(ctx context.Context, e *emptypb.Empty) (*pb.GroupMembers, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	groups := &pb.GroupMembers{}
	for group, members := range s.agentService.GroupMembers() {
		var memberIDs []string
		for _, member := range members {
			memberIDs = append(memberIDs, member.String())
		}
		groups.Members = append(groups.Members, &pb.GroupMember{Group: group, Members: memberIDs})
	}
	return groups, nil
}

// GroupRemove removes an Agent from an Agent group
func (s *Server) GroupRemove(ctx context.Context, in *pb.Group) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentUUID, err := uuid.Parse(in.AgentID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.AgentID, err)
		slog.Error(err.Error())
		return
	}

	err = s.agentService.RemoveAgentFromGroup(in.Group, agentUUID)
	if err != nil {
		err = fmt.Errorf("there was an error removing agent %s from group %s: %s", agentUUID, in.Group, err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Agent %s removed from group %s", in.AgentID, in.Group))
	return
}

// Groups return a list of all Agent groups on the RPC server
func (s *Server) Groups(ctx context.Context, e *emptypb.Empty) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	out := &pb.Slice{}
	out.Data = s.agentService.Groups()
	return out, nil
}

// lastCheckin returns a nicely formatted string for time since the last checkin (HH:MM:SS)
func lastCheckin(t time.Time) string {
	lastTime := time.Since(t)
	lastTimeStr := fmt.Sprintf("%d:%02d:%02d ago",
		int(lastTime.Hours()),
		int(lastTime.Minutes())%60,
		int(lastTime.Seconds())%60)
	return lastTimeStr
}

// Note sets a note on the Agent's Note field
// args[0:] = the note to set
func (s *Server) Note(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Parse the UUID from the request
	agentID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	err = s.agentService.UpdateNote(agentID, strings.Join(in.Arguments, " "))
	if err != nil {
		err = fmt.Errorf("there was an error updating the agent's note: %s", err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Successfully set note for agent %s", agentID))
	return
}

// Remove deletes the agent from the server
func (s *Server) Remove(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	msg = &pb.Message{}
	// Parse the UUID from the request
	agentUUID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id, err)
		slog.Error(err.Error())
		return
	}
	err = s.agentService.Remove(agentUUID)
	if err == nil {
		msg = NewPBSuccessMessage(fmt.Sprintf("Agent %s was removed from the server", agentUUID))
	}
	return
}
