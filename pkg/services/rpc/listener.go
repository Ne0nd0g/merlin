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
	"time"

	// 3rd Party
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	l2 "github.com/Ne0nd0g/merlin/v2/pkg/listeners"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
)

/* RPC METHODS TO INTERACT WITH THE LISTENER SERVICE*/

// CreateListener instantiates a new Listener on the RPC server
func (s *Server) CreateListener(ctx context.Context, in *pb.Options) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	// Create the listener
	listener, err := s.ls.NewListener(in.Options)
	if err != nil {
		err = fmt.Errorf("there was an error creating the listener: %s", err)
		return
	}
	// The Message field must only contain the string representation of the UUID
	// The client can infer success when the Error is false
	msg = NewPBSuccessMessage(listener.ID().String())
	return
}

// GetListenerDefaultOptions returns all the available options for a listener type, not for a previously instantiated listener
func (s *Server) GetListenerDefaultOptions(ctx context.Context, in *pb.String) (options *pb.Options, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	o, err := s.ls.DefaultOptions(in.Data)
	if err != nil {
		err = fmt.Errorf("there was an error getting the default options for listener '%s': %s", in.Data, err)
		slog.Error(err.Error())
		return
	}
	options = &pb.Options{
		Options: o,
	}
	return
}

// GetListenerIDs returns a list of all the previously instantiated listeners on the RPC server
func (s *Server) GetListenerIDs(ctx context.Context, e *emptypb.Empty) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	var listenerIDs []string
	for _, l := range s.ls.Listeners() {
		listenerIDs = append(listenerIDs, l.ID().String())
	}
	return &pb.Slice{Data: listenerIDs}, nil
}

// GetListenerOptions returns a previously instantiated listener's options
func (s *Server) GetListenerOptions(ctx context.Context, id *pb.ID) (options *pb.Options, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID
	listenerID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return
	}

	listener, err := s.ls.Listener(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error getting listener %s: %s", listenerID, err)
		slog.Error(err.Error())
		return
	}

	options = &pb.Options{
		Options: listener.ConfiguredOptions(),
	}
	return
}

// GetListeners returns a list of all instantiated Listeners
func (s *Server) GetListeners(ctx context.Context, e *emptypb.Empty) (table *pb.TableData, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	table = &pb.TableData{
		Header: []string{"ID", "NAME", "INTERFACE", "PROTOCOL", "STATUS", "DESCRIPTION"},
	}

	for _, l := range s.ls.Listeners() {
		if l.Server() != nil {
			server := *l.Server()
			row := []string{
				l.ID().String(),
				l.Name(),
				fmt.Sprintf("%s:%d", server.Interface(), server.Port()),
				server.ProtocolString(),
				l.Status(),
				l.Description(),
			}
			table.Rows = append(table.Rows, &pb.TableRows{Row: row})
		} else {
			row := []string{
				l.ID().String(),
				l.Name(),
				l.Addr(),
				l2.String(l.Protocol()),
				l.Status(),
				l.Description(),
			}
			table.Rows = append(table.Rows, &pb.TableRows{Row: row})
		}

	}
	return
}

// GetListenerStatus returns the status of a previously instantiated listener
func (s *Server) GetListenerStatus(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID
	listenerID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return
	}
	l, err := s.ls.Listener(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error getting listener %s: %s", listenerID, err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBPlainMessage(l.Status())
	return
}

// GetListenerTypes returns a list of all available Listener types (e.g. http, tcp, etc.)
func (s *Server) GetListenerTypes(ctx context.Context, e *emptypb.Empty) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	return &pb.Slice{Data: s.ls.ListenerTypes()}, nil
}

// RemoveListener deletes an instantiated Listener on the RPC server
func (s *Server) RemoveListener(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID from the request
	listenerID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return
	}
	err = s.ls.Remove(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error removing listener %s: %s", listenerID, err)
		slog.Error(err.Error())
		return
	}
	err = s.ls.RemoveFromPersist(listenerID)
	if err != nil {
		msg = NewPBErrorMessage(err)
		err = nil
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Successfully removed listener %s", listenerID))
	return
}

// RestartListener restarts a listener on the RPC server
func (s *Server) RestartListener(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID from the request
	listenerID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return
	}
	err = s.ls.Restart(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error restarting listener %s: %s", listenerID, err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Successfully restarted listener %s", listenerID))
	return
}

// Servers return a list of supported listener types
func (s *Server) Servers(ctx context.Context, e *emptypb.Empty) (*pb.Slice, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	servers := s.ls.ListenerTypes()
	return &pb.Slice{Data: servers}, nil
}

// SetListenerOption modifies a configurable listener option on the RPC server
func (s *Server) SetListenerOption(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	if len(in.Arguments) < 2 {
		err = fmt.Errorf("the SetListenerOption RPC call requires at least two arguments, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}

	// Parse the UUID from the request
	listenerID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	err = s.ls.SetOption(listenerID, in.Arguments[0], in.Arguments[1])
	if err != nil {
		err = fmt.Errorf("there was an error setting the listener option: %s", err)
		slog.Error(err.Error())
		return
	}

	err = s.ls.UpdatePersistValue(listenerID, in.Arguments[0], in.Arguments[1])
	if err != nil {
		err = fmt.Errorf("there was an error setting the listener option: %s", err)
		slog.Error(err.Error())
		return
	}

	msg = NewPBSuccessMessage(fmt.Sprintf("set %s to: %s", in.Arguments[0], in.Arguments[1]))
	return
}

// StartListener starts a previously instantiated listener on the RPC server
func (s *Server) StartListener(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Validate id is a UUID
	var listenerID uuid.UUID
	listenerID, err = uuid.Parse(id.Id)
	if err != nil {
		msg = NewPBErrorMessage(fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err))
		err = nil
		return
	}

	// Start the listener
	err = s.ls.Start(listenerID)
	if err != nil {
		msg = NewPBErrorMessage(err)
		err = nil
		return
	}

	err = s.ls.Persist(listenerID)
	if err != nil {
		msg = NewPBErrorMessage(err)
		err = nil
		return
	}

	// Get the instantiated Listener from the repository
	l, err := s.ls.Listener(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error getting listener %s: %s", listenerID, err)
		return
	}

	if l.Server() != nil {
		server := *l.Server()
		m := fmt.Sprintf("Started '%s' listener with an ID of %s and a %s server on %s:%d",
			l.Name(), l.ID(), server.ProtocolString(), server.Interface(), server.Port())
		msg = &pb.Message{
			Level:     pb.MessageLevel_SUCCESS,
			Message:   m,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		return
	}

	// Not all listeners have an infrastructure layer server
	msg = &pb.Message{
		Level:     pb.MessageLevel_SUCCESS,
		Message:   fmt.Sprintf("Started '%s' listener with an ID of %s", l.Name(), l.ID()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	return
}

// StopListener stops a previously instantiated listener on the RPC server
func (s *Server) StopListener(ctx context.Context, id *pb.ID) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID
	listenerID, err := uuid.Parse(id.Id)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", id.Id, err)
		slog.Error(err.Error())
		return
	}

	err = s.ls.Stop(listenerID)
	if err != nil {
		err = fmt.Errorf("there was an error stopping listener %s: %s", listenerID, err)
		slog.Error(err.Error())
		return
	}

	err = s.ls.RemoveFromPersist(listenerID)
	if err != nil {
		msg = NewPBErrorMessage(err)
		err = nil
		return
	}
	msg = NewPBSuccessMessage(fmt.Sprintf("Successfully stopped listener %s", listenerID))
	return
}
