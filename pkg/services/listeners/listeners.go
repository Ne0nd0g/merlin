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

// Package listeners is a service for creating and managing Listener objects
package listeners

import (
	// Standard
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	// 3rd Party
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"

	// Merlin
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/http"
	httpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/http/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/smb"
	smbMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/smb/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/tcp"
	tcpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/tcp/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/listeners/udp"
	udpMemory "github.com/Ne0nd0g/merlin/v2/pkg/listeners/udp/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/servers"
	httpServer "github.com/Ne0nd0g/merlin/v2/pkg/servers/http"
	httpServerRepo "github.com/Ne0nd0g/merlin/v2/pkg/servers/http/memory"
)

// ListenerService is a structure that implements the service methods holding references to Listener & Server repositories
type ListenerService struct {
	httpRepo       http.Repository
	httpServerRepo httpServer.Repository
	smbRepo        smb.Repository
	tcpRepo        tcp.Repository
	udpRepo        udp.Repository
	storageFile    string // is used for listeners persistence
}

// NewListenerService is a factory to create and return a ListenerService
func NewListenerService() (ls ListenerService) {
	ls.httpRepo = WithHTTPMemoryListenerRepository()
	ls.httpServerRepo = WithHTTPMemoryServerRepository()
	ls.smbRepo = WithSMBMemoryListenerRepository()
	ls.tcpRepo = WithTCPMemoryListenerRepository()
	ls.udpRepo = WithUDPMemoryListenerRepository()
	return
}

// WithHTTPMemoryListenerRepository retrieves an in-memory HTTP Listener repository interface used to manage Listener objects
func WithHTTPMemoryListenerRepository() http.Repository {
	return httpMemory.NewRepository()
}

// WithHTTPMemoryServerRepository retrieves an in-memory HTTP Server repository interface used to manage Server objects
func WithHTTPMemoryServerRepository() httpServer.Repository {
	return httpServerRepo.NewRepository()
}

// WithSMBMemoryListenerRepository retrieves an in-memory TCP Listener repository interface used to manage Listener objects
func WithSMBMemoryListenerRepository() smb.Repository {
	return smbMemory.NewRepository()
}

// WithTCPMemoryListenerRepository retrieves an in-memory TCP Listener repository interface used to manage Listener objects
func WithTCPMemoryListenerRepository() tcp.Repository {
	return tcpMemory.NewRepository()
}

func WithUDPMemoryListenerRepository() udp.Repository {
	return udpMemory.NewRepository()
}

// NewListener is a factory that takes in a map of options used to configure a Listener, adds the Listener to its
// respective repository, and returns a copy created Listener object
func (ls *ListenerService) NewListener(options map[string]string) (listener listeners.Listener, er error) {
	// Determine the infrastructure layer server
	if _, ok := options["Protocol"]; !ok {
		return nil, fmt.Errorf("pkg/services/listeners.NewListener(): the options map did not contain the \"Protocol\" key")
	}

	switch strings.ToLower(options["Protocol"]) {
	//case servers.HTTP, servers.HTTPS, servers.H2C, servers.HTTP2, servers.HTTP3:
	case "http", "https", "h2c", "http2", "http3":
		hServer, err := httpServer.New(options)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		err = ls.httpServerRepo.Add(hServer)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		// Create a new HTTP Listener
		hListener, err := http.NewHTTPListener(&hServer, options)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		// Store the HTTP Listener
		err = ls.httpRepo.Add(hListener)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		slog.Info("Create new listener", "protocol", hServer.ProtocolString(), "address", hServer.Addr(), "name", hListener.Name(), "id", hListener.ID(), "authenticator", hListener.Authenticator().String(), "transforms", fmt.Sprintf("%+v", hListener.Transformers()))
		listener = &hListener
		return
	case "smb":
		// Create a new SMB Listener
		sListener, err := smb.NewSMBListener(options)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		// Store the SMB Listener
		err = ls.smbRepo.Add(sListener)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		slog.Info("Create new listener", "protocol", options["Protocol"], "address", sListener.Addr(), "name", sListener.Name(), "id", sListener.ID(), "authenticator", sListener.Authenticator().String(), "transforms", fmt.Sprintf("%+v", sListener.Transformers()))
		listener = &sListener
		return
	case "tcp":
		// Create a new TCP Listener
		tListener, err := tcp.NewTCPListener(options)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		// Store the TCP Listener
		err = ls.tcpRepo.Add(tListener)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		slog.Info("Create new listener", "protocol", options["Protocol"], "address", tListener.Addr(), "name", tListener.Name(), "id", tListener.ID(), "authenticator", tListener.Authenticator().String(), "transforms", fmt.Sprintf("%+v", tListener.Transformers()))
		listener = &tListener
		return
	case "udp":
		uListener, err := udp.NewUDPListener(options)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		// Store the TCP Listener
		err = ls.udpRepo.Add(uListener)
		if err != nil {
			return nil, fmt.Errorf("pkg/services/listeners.NewListener(): %s", err)
		}
		slog.Info("Create new listener", "protocol", options["Protocol"], "address", uListener.Addr(), "name", uListener.Name(), "id", uListener.ID(), "authenticator", uListener.Authenticator().String(), "transforms", fmt.Sprintf("%+v", uListener.Transformers()))
		listener = &uListener
		return
	default:
		return nil, fmt.Errorf("pkg/services/listeners.NewListener(): unhandled server type %d", servers.FromString(options["Protocol"]))
	}
}

// CLICompleter returns a list of Listener & Server types that Merlin supports for CLI tab completion
func (ls *ListenerService) CLICompleter() func(string) []string {
	return func(line string) []string {
		var s []string
		l := listeners.Listeners()
		for _, listener := range l {
			switch listener {
			case listeners.HTTP:
				srvs := servers.RegisteredServers
				for k := range srvs {
					s = append(s, servers.Protocol(k))
				}
			default:
				s = append(s, listeners.String(listener))
			}
		}
		return s
	}
}

// DefaultOptions gets the default configurable options for both the listener and the infrastructure layer server (if applicable)
func (ls *ListenerService) DefaultOptions(protocol string) (options map[string]string, err error) {
	var listenerOptions map[string]string
	var serverOptions map[string]string
	switch listeners.FromString(protocol) {
	case listeners.HTTP:
		// Listener options
		listenerOptions = http.DefaultOptions()
		// Server, infrastructure layer, options
		serverOptions = httpServer.GetDefaultOptions(servers.FromString(protocol))
	case listeners.SMB:
		listenerOptions = smb.DefaultOptions()
	case listeners.TCP:
		listenerOptions = tcp.DefaultOptions()
	case listeners.UDP:
		listenerOptions = udp.DefaultOptions()
	default:
		err = fmt.Errorf("pkg/services/listeners.DefaultOptions(): unhandled server type: %s", protocol)
		return
	}

	// Add Server options (if any) to Listener options
	for k, v := range serverOptions {
		listenerOptions[k] = v
	}

	// Sort the keys
	var keys []string
	for key := range listenerOptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	options = make(map[string]string, len(listenerOptions))
	for _, key := range keys {
		options[key] = listenerOptions[key]
	}
	return
}

// List returns a list of Listener names that exist and is used for command line tab completion
func (ls *ListenerService) List() func(string) []string {
	return func(line string) []string {
		return ls.ListenerNames()
	}
}

// Listener returns a Listener object for the input ID
func (ls *ListenerService) Listener(id uuid.UUID) (listeners.Listener, error) {
	httpListener, err := ls.httpRepo.ListenerByID(id)
	if err == nil {
		return &httpListener, nil
	}
	smbListener, err := ls.smbRepo.ListenerByID(id)
	if err == nil {
		return &smbListener, nil
	}
	tcpListener, err := ls.tcpRepo.ListenerByID(id)
	if err == nil {
		return &tcpListener, nil
	}
	udpListener, err := ls.udpRepo.ListenerByID(id)
	if err == nil {
		return &udpListener, nil
	}
	return nil, fmt.Errorf("pkg/services/listeners.GetListenerByID(): could not find listener %s", id)
}

// Listeners returns a list of stored Listener objects
func (ls *ListenerService) Listeners() (listenerList []listeners.Listener) {
	// HTTP Listeners
	httpListeners := ls.httpRepo.Listeners()
	for i := range httpListeners {
		listenerList = append(listenerList, &httpListeners[i])
	}
	// SMB Listeners
	smbListeners := ls.smbRepo.Listeners()
	for i := range smbListeners {
		listenerList = append(listenerList, &smbListeners[i])
	}
	// TCP Listeners
	tcpListeners := ls.tcpRepo.Listeners()
	for i := range tcpListeners {
		listenerList = append(listenerList, &tcpListeners[i])
	}
	// UDP Listeners
	udpListeners := ls.udpRepo.Listeners()
	for i := range udpListeners {
		listenerList = append(listenerList, &udpListeners[i])
	}
	return
}

// ListenerNames returns a list of Listener names as a string
func (ls *ListenerService) ListenerNames() (names []string) {
	// HTTP Listeners
	httpListeners := ls.httpRepo.Listeners()
	for _, listener := range httpListeners {
		names = append(names, listener.Name())
	}
	// SMB Listeners
	smbListeners := ls.smbRepo.Listeners()
	for _, listener := range smbListeners {
		names = append(names, listener.Name())
	}
	// TCP Listeners
	tcpListeners := ls.tcpRepo.Listeners()
	for _, listener := range tcpListeners {
		names = append(names, listener.Name())
	}
	// UDP Listeners
	udpListeners := ls.udpRepo.Listeners()
	for _, listener := range udpListeners {
		names = append(names, listener.Name())
	}
	return
}

// ListenerTypes returns a list of Listener types as a string (e.g. HTTP, SMB, TCP, UDP)
func (ls *ListenerService) ListenerTypes() (types []string) {
	// TODO Create a function to dynamically enumerate available listener types
	types = append(types, "HTTP")
	types = append(types, "HTTPS")
	types = append(types, "H2C")
	types = append(types, "HTTP2")
	types = append(types, "HTTP3")
	types = append(types, "SMB")
	types = append(types, "TCP")
	types = append(types, "UDP")
	return
}

// ListenerByName returns the first Listener object that matches the input name
func (ls *ListenerService) ListenerByName(name string) (listeners.Listener, error) {
	listener, err := ls.httpRepo.ListenerByName(name)
	if err == nil {
		return &listener, err
	}
	smbListener, err := ls.smbRepo.ListenerByName(name)
	if err == nil {
		return &smbListener, err
	}
	tcpListener, err := ls.tcpRepo.ListenerByName(name)
	if err == nil {
		return &tcpListener, err
	}
	udpListener, err := ls.udpRepo.ListenerByName(name)
	if err == nil {
		return &udpListener, err
	}
	return nil, fmt.Errorf("pkg/services/listeners.GetListenerByName(): %s", err)
}

// ListenersByType returns a list of all stored listeners for the provided listener
func (ls *ListenerService) ListenersByType(protocol int) (listenerList []listeners.Listener) {
	switch protocol {
	case listeners.HTTP:
		httpListeners := ls.httpRepo.Listeners()
		for i := range httpListeners {
			listenerList = append(listenerList, &httpListeners[i])
		}
	case listeners.SMB:
		smbListeners := ls.smbRepo.Listeners()
		for i := range smbListeners {
			listenerList = append(listenerList, &smbListeners[i])
		}
	case listeners.TCP:
		tcpListeners := ls.tcpRepo.Listeners()
		for i := range tcpListeners {
			listenerList = append(listenerList, &tcpListeners[i])
		}
	case listeners.UDP:
		udpListeners := ls.udpRepo.Listeners()
		for i := range udpListeners {
			listenerList = append(listenerList, &udpListeners[i])
		}
	}
	return
}

// Remove deletes the Listener from its repository
func (ls *ListenerService) Remove(id uuid.UUID) error {
	listener, err := ls.Listener(id)
	if err != nil {
		return err
	}
	// Stop the server before removing it but don't handle any errors
	server := *listener.Server()
	err = server.Stop()
	if err != nil {
		return err
	}
	switch listener.Protocol() {
	case listeners.HTTP:
		return ls.httpRepo.RemoveByID(id)
	case listeners.SMB:
		return ls.smbRepo.RemoveByID(id)
	case listeners.TCP:
		return ls.tcpRepo.RemoveByID(id)
	case listeners.UDP:
		return ls.udpRepo.RemoveByID(id)
	default:
		return fmt.Errorf("pkg/services/listeners.Remove(): unhandled listener protocol type %d for listener %s", listener.Protocol(), id)
	}
}

// Restart terminates a Listener's embedded Server object (if applicable) and then starts it again
func (ls *ListenerService) Restart(id uuid.UUID) error {
	// Get the listener
	listener, err := ls.Listener(id)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Restart(): %s", err)
	}
	server := *listener.Server()
	err = server.Stop()
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Restart(): %s", err)
	}
	go server.Start()
	return nil
}

// SetOption updates an existing Listener's configurable option with the value provided
func (ls *ListenerService) SetOption(id uuid.UUID, option, value string) error {
	listener, err := ls.Listener(id)
	if err != nil {
		return err
	}
	switch listener.Protocol() {
	case listeners.HTTP:
		return ls.httpRepo.SetOption(id, option, value)
	case listeners.SMB:
		return ls.smbRepo.SetOption(id, option, value)
	case listeners.TCP:
		return ls.tcpRepo.SetOption(id, option, value)
	case listeners.UDP:
		return ls.udpRepo.SetOption(id, option, value)
	default:
		return fmt.Errorf("pkg/services/listeners.SetOptions(): unhandled protocol %d for listener %s", listener.Protocol(), id)
	}
}

// Start initiates the Listener's embedded Server object (if applicable) to start listening and responding to Agent communications
func (ls *ListenerService) Start(id uuid.UUID) error {

	// Get the listener
	listener, err := ls.Listener(id)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Start(): %s", err)
	}
	switch listener.Protocol() {
	case listeners.HTTP:
		server := *listener.Server()
		err = server.Listen()
		if err != nil {
			return err
		}
		// Start() does not return until the transport server is killed and therefore must be run in a go routine
		go server.Start()
		return nil
	case listeners.SMB:
		return nil
	case listeners.TCP:
		// Nothing to do, there is not an infrastructure layer server to start for the TCP listener
		return nil
	case listeners.UDP:
		return nil
	default:
		return fmt.Errorf("pkg/services/listeners.Start(): unhandled listener protocol: %d", listener.Protocol())
	}
}

// Stop terminates the Listener's embedded Server object (if applicable) to stop it listening for incoming Agent messages
func (ls *ListenerService) Stop(id uuid.UUID) error {
	// Get the listener
	listener, err := ls.Listener(id)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Restart(): %s", err)
	}
	if listener.Protocol() == listeners.HTTP {
		server := *listener.Server()
		return server.Stop()
	}
	return nil
}

// Persist the embedded server object of the listener (if applicable) so that it can be used again after a server restart.
func (ls *ListenerService) Persist(id uuid.UUID) error {
	file, err := os.OpenFile(ls.storageFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Persist(): error on create or append to file: %s", err)
	}
	defer file.Close()

	listener, err := ls.Listener(id)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Persist(): %s", err)
	}

	var listenersData = map[string]map[string]string{}
	listenersData[listener.ID().String()] = listener.ConfiguredOptions()
	persistData, err := yaml.Marshal(listenersData)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.Persist(): unmarshal error on persist file: %s", err)
	}

	if _, err = file.Write(persistData); err != nil {
		return fmt.Errorf("pkg/services/listeners.Persist(): error on persist file: %s", err)
	}

	return nil
}

// RemoveFromPersist the embedded server object of the listener (if applicable) so that it cannot be used again after a server restart.
func (ls *ListenerService) RemoveFromPersist(id uuid.UUID) error {
	file, err := os.OpenFile(ls.storageFile, os.O_RDWR, 0640)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): error on open file: %s", err)
	}
	defer file.Close()

	fb := bytes.Buffer{}
	_, err = fb.ReadFrom(file)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): error on read file: %s", err)
	}

	var listenersData = map[string]map[string]string{}
	err = yaml.Unmarshal(fb.Bytes(), listenersData)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): unmarshal error on persist file: %s", err)
	}
	delete(listenersData, id.String())

	// Clean the file an write back the file
	file.Truncate(0)
	file.Seek(0, 0)

	if len(listenersData) != 0 {
		persistData, err := yaml.Marshal(listenersData)
		if err != nil {
			return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): unmarshal error on persist file: %s", err)
		}

		if _, err = file.Write(persistData); err != nil {
			return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): error on persist file: %s", err)
		}
	}

	return nil
}

// UpdatePersistValue updates the embedded server object value of the listener (if applicable) so that it can be used again after a server restart.
func (ls *ListenerService) UpdatePersistValue(id uuid.UUID, option, value string) error {
	file, err := os.OpenFile(ls.storageFile, os.O_RDWR, 0640)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.UpdatePersistValue(): error on open file: %s", err)
	}
	defer file.Close()

	fb := bytes.Buffer{}
	_, err = fb.ReadFrom(file)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.UpdatePersistValue(): error on read file: %s", err)
	}

	listener, err := ls.Listener(id)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.UpdatePersistValue(): %s", err)
	}

	var listenersData = map[string]map[string]string{}
	err = yaml.Unmarshal(fb.Bytes(), listenersData)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.UpdatePersistValue(): unmarshal error on persist file: %s", err)
	}

	listenersData[listener.ID().String()][option] = value

	file.Truncate(0)
	file.Seek(0, 0)

	persistData, err := yaml.Marshal(listenersData)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): unmarshal error on persist file: %s", err)
	}

	if _, err = file.Write(persistData); err != nil {
		return fmt.Errorf("pkg/services/listeners.RemoveFromPersist(): error on persist file: %s", err)
	}

	return nil
}

// LoadListenersFromFile restores the listeners from a YAML file
func (ls *ListenerService) LoadListenersFromFile(file string) error {
	f, err := os.OpenFile(file, os.O_RDWR, 0640)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.LoadListenersFromFile(): error on open file: %s", err)
	}
	defer f.Close()

	fb := bytes.Buffer{}
	_, err = fb.ReadFrom(f)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.LoadListenersFromFile(): error on read file: %s", err)
	}

	var listenersData = map[string]map[string]string{}
	err = yaml.Unmarshal(fb.Bytes(), listenersData)
	if err != nil {
		return fmt.Errorf("pkg/services/listeners.LoadListenersFromFile(): unmarshal error on persist file: %s", err)
	}

	for _, v := range listenersData {
		l, err := ls.NewListener(v)
		if err != nil {
			return err
		}
		err = ls.Start(l.ID())
		if err != nil {
			return err
		}
	}
	return nil
}

// SetStorageFile set and returns the location of the persist listeners
func (ls *ListenerService) SetStorageFile(storageFile string) {
	ls.storageFile = storageFile
}
