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

package cli

import (
	"bufio"
	// Standard
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/message"

	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Merlin
	merlin "github.com/Ne0nd0g/merlin/pkg"
	// Internal - CLI
	"github.com/Ne0nd0g/merlin/pkg/cli/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/repository"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	merlinOS "github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener"
	lmemory "github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	mmemory "github.com/Ne0nd0g/merlin/pkg/cli/message/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/services/rpc"
)

// Service is a structure for the CLI service that holds the state of the CLI
type Service struct {
	id           uuid.UUID           // id is the unique identifier for the CLI service
	agent        uuid.UUID           // agent is the unique identifier for the Agent the CLI is interacting with
	agentOS      merlinOS.OS         // agentOS is the operating system of the Agent the CLI is interacting with
	listener     uuid.UUID           // listener is the unique identifier for the Listener the CLI is interacting with
	commandRepo  commands.Repository // commandRepo is the repository of commands the CLI can execute
	listenerRepo listener.Repository // listenerRepo is the repository of listeners the CLI can interact with
	messageRepo  message.Repository  // messageRepo is the repository of user messages displayed on the CLI
	prompt       *readline.Instance  // prompt is the visual string displayed to the user as well as other components such as tab completion
	menu         menu.Menu           // menu is the current menu the CLI is in
	module       uuid.UUID           // module is the unique identifier for the Module the CLI is interacting with
	rpcService   *rpc.Service        // rpcService is the gRPC client service for the CLI
	sync.Mutex
}

// services in the instantiated Service structure for this CLI service
var service *Service

// pkg is a string containing the package name for this file used with error messages
var pkg = "pkg/cli/services/cli"

// NewCLIService is a factory that creates a new CLI service
func NewCLIService(password string, secure bool, tlsKey, tlsCert, tlsCA string) *Service {
	if service == nil {
		config := &readline.Config{
			Prompt:            "\033[31mMerlin»\033[0m ",
			HistoryFile:       path.Join(core.CurrentDir, "data", "log", "readline.tmp"),
			InterruptPrompt:   "^C",
			EOFPrompt:         "exit",
			HistorySearchFold: true,
			FuncFilterInputRune: func(r rune) (rune, bool) {
				switch r {
				// block CtrlZ feature
				case readline.CharCtrlZ:
					return r, false
				}
				return r, true
			},
		}
		prompt, err := readline.NewEx(config)
		if err != nil {
			log.Fatalf("There was an error creating the CLI prompt: %s", err)
		}
		service = &Service{
			commandRepo:  withMemoryCommandRepository(),
			listenerRepo: withMemoryListenerRepository(),
			messageRepo:  withMemoryMessageRepository(),
			menu:         menu.MAIN,
			prompt:       prompt,
			id:           uuid.NewV4(),
			agent:        uuid.Nil,
			listener:     uuid.Nil,
		}

		service.rpcService, err = rpc.NewRPCService(password, secure, tlsKey, tlsCert, tlsCA)
		if err != nil {
			log.Fatalf("there was an error creating the CLI service: %s", err)
		}
		service.prompt.Config.AutoComplete = service.completer()
	}
	return service
}

// withMemoryCommandRepository calls a factory that creates a new in-memory command repository
func withMemoryCommandRepository() commands.Repository {
	return repository.NewRepository()
}

// withMemoryListenerRepository calls a factory that creates a new in-memory listener repository
func withMemoryListenerRepository() listener.Repository {
	return lmemory.NewRepository()
}

// withMemoryMessageRepository calls a factory that creates a new in-memory message repository
func withMemoryMessageRepository() message.Repository {
	return mmemory.NewRepository()
}

// Run is the main entry point for the CLI service called by the main package
func (s *Service) Run(addr string) {
	logging()
	slog.Info(fmt.Sprintf("Starting Merlin version: %s, build: %s, client ID: %s", merlin.Version, merlin.Build, s.id))
	s.osSignalHandler()
	s.displayUserMessages()

	// Display the Merlin banner
	display := color.BlueString(banner.MerlinBanner1)
	display += color.BlueString(fmt.Sprintf("\n\t\t\tVersion: %s\n", merlin.Version))
	display += color.BlueString(fmt.Sprintf("\t\t\tBuild: %s\n", merlin.Build))
	msg := message.NewUserMessage(message.Plain, display)
	s.messageRepo.Add(msg)

	// Make gRPC connection to the Merlin server
	err := s.rpcService.Connect(addr)
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error connecting to the Merlin server: %s", err))
		s.messageRepo.Add(msg)
	}

	// Start infinite loop to process command line input
	for {
		// Read command line input
		var line string
		line, err = s.prompt.Readline()

		// Handle Ctrl+C
		if err == readline.ErrInterrupt {
			if s.confirm("Are you sure you want to quit the server?") {
				slog.Info("[!]Quitting...")
				os.Exit(0)
			}
		} else if err == io.EOF {
			if s.confirm("Are you sure you want to quit the server?") {
				slog.Info("[!]Quitting...")
				os.Exit(0)
			}
		}

		line = strings.TrimSpace(line)
		var cmd []string
		cmd, err = shellwords.Parse(line)
		if err != nil {
			msg = message.NewErrorMessage(fmt.Errorf("there was an error parsing command line arguments: %s", err))
			s.messageRepo.Add(msg)
		}

		if len(cmd) > 0 {
			switch s.menu {
			case menu.MAIN:
				s.handle(line)
			default:
				s.handle(line)
			}
		}
	}
}

// handle processes the user input and executes the appropriate command
func (s *Service) handle(input string) {
	slog.Info(fmt.Sprintf("Command entered: %s", input))
	if len(input) <= 0 {
		msg := message.NewUserMessage(message.Warn, fmt.Sprintf("%s.handle(): no input provided", pkg))
		s.messageRepo.Add(msg)
		return
	}

	command := strings.Split(input, " ")
	if len(command) <= 0 {
		msg := message.NewUserMessage(message.Warn, fmt.Sprintf("%s.handle(): no command provided", pkg))
		s.messageRepo.Add(msg)
		return
	}

	switch strings.ToLower(command[0]) {
	case "help", "--help", "-h", "?", "/?":
		if len(command) > 1 {
			// Get help for a specific command
			input = fmt.Sprintf("%s help", command[1])
			command = []string{command[1]}
		} else {
			s.help()
			return
		}
	case "queue":
		// Must process queue command here because it subsequently calls other commands
		s.queueCommand(input)
		return
	}

	// Set up the UUID for the command
	id := uuid.Nil
	switch s.menu {
	case menu.AGENT:
		id = s.agent
	case menu.LISTENER, menu.LISTENERSETUP:
		id = s.listener
	case menu.MODULE:
		id = s.module
	}

	// Get the command from the repository
	cmd, err := s.commandRepo.Get(s.menu, command[0])
	if err != nil {
		var msg *message.UserMessage
		switch err {
		case repository.ErrCommandNotFound:
			msg = message.NewErrorMessage(fmt.Errorf("'%s' is not a valid command", command[0]))
		case repository.ErrCommandNotInMenu:
			msg = message.NewErrorMessage(fmt.Errorf("'%s' is not a valid command for this '%s' menu", command[0], s.menu.String()))
		default:
			msg = message.NewErrorMessage(fmt.Errorf("%s.handle(): %s", pkg, err))
		}
		s.messageRepo.Add(msg)
		return
	}

	// Validate the command can be used with the Agent's operating system
	if s.menu == menu.AGENT {
		if s.agentOS == merlinOS.UNDEFINED {
			// There is time between when the Agent first checks in, and when it sends back its configuration.
			// Update it to all so that all commands are available to the Agent when we don't know the OS
			s.agentOS = merlinOS.ALL
		}
		// See if we know the Agent's OS now
		if s.agentOS == merlinOS.ALL {
			a, errRPC := rpc.GetAgent(s.agent)
			if errRPC != nil {
				msg := message.NewErrorMessage(fmt.Errorf("there was an error making the GetAgent RPC call: %s", errRPC))
				s.messageRepo.Add(msg)
				return
			}
			o := merlinOS.FromString(a.Host().Platform)
			// Update the Agent's OS know that we know it
			if o != merlinOS.UNDEFINED && o != merlinOS.LOCAL {
				s.agentOS = o
			}
		}

		// See if the command is supported by the Agent's OS
		// 1. The Agent's OS doesn't match the command's OS
		// 2. The Agent's OS is not ALL, used when we don't know the Agent's OS to ensure all commands are accessible
		// 3. The command's OS is not ALL, because if it is, then it doesn't matter that we don't know the Agent's OS
		// 4. The command's OS is not LOCAL, because if it is, then it doesn't matter that we don't know the Agent's OS
		if s.agentOS != cmd.OS() && s.agentOS != merlinOS.ALL && cmd.OS() != merlinOS.ALL && cmd.OS() != merlinOS.LOCAL {
			msg := message.NewUserMessage(message.Warn, fmt.Sprintf("The '%s' command is for the %s operating system and not supported for this agent's operating system (%s)", cmd, cmd.OS(), s.agentOS))
			s.messageRepo.Add(msg)
			return
		}
	}

	// Send the original input so the command can decide how to parse it
	resp := cmd.Do(s.menu, id, input)
	if resp.Message != nil {
		if resp.Message.Error() {
			s.messageRepo.Add(resp.Message)
			return
		}
	}

	// Check if the Menu has changed
	//fmt.Printf("Response Menu: %s(%d)\n", resp.Menu, resp.Menu)
	if resp.Menu != menu.NONE {
		s.menu = resp.Menu
	}
	// Check if the prompt has changed
	if resp.Prompt != "" {
		s.prompt.SetPrompt(resp.Prompt)
	}
	// Check if the active Agent ID has changed
	if resp.Agent != uuid.Nil {
		s.agent = resp.Agent
		s.agentOS = resp.AgentOS
	}
	// Check if the active Listener ID has changed
	if resp.Listener != uuid.Nil {
		s.listener = resp.Listener
	}
	// Check if the active Module ID has changed
	if resp.Module != uuid.Nil {
		s.module = resp.Module
	}
	// Check if there is a UserMessage to send
	if resp.Message != nil {
		s.messageRepo.Add(resp.Message)
	}
	// Set the completer
	comp := s.completer()
	if comp != nil {
		s.prompt.Config.AutoComplete = comp
	}

	return
}

// help prints a table of commands, their descriptions, and their usage string that are available for the current menu
func (s *Service) help() {
	// Table of command, description, usage
	var data [][]string
	cmds := s.commandRepo.GetAll()
	for _, cmd := range cmds {
		if cmd.Menu(s.menu) {
			if s.menu == menu.AGENT {
				// If we don't know what operating system the Agent is running on, try to update it
				if s.agentOS == merlinOS.UNDEFINED {
					if s.agent != uuid.Nil {
						a, err := rpc.GetAgent(s.agent)
						if err != nil {
							if core.Debug {
								msg := message.NewErrorMessage(fmt.Errorf("there was an error trying to update the Agent's OS when"+
									" making the GetAgent API call to filter the commands displayed in help "+
									"menu: %s", err))
								s.messageRepo.Add(msg)
							}
						}
						o := merlinOS.FromString(a.Host().Platform)
						// Update the Agent's OS know that we know it
						if o != merlinOS.UNDEFINED && o != merlinOS.LOCAL {
							s.agentOS = o
						}
					}
				}
				// If the Agent's OS is ALL or UNDEFINED, add the command help
				// If the command's OS is ALL or LOCAL, add the command help
				if cmd.OS() == merlinOS.ALL || cmd.OS() == merlinOS.LOCAL || s.agentOS == merlinOS.UNDEFINED || s.agentOS == merlinOS.ALL {
					// Continue on to the code below to add the command to the help table
				} else if s.agentOS != cmd.OS() {
					// Do not add the command because it is not supported by the Agent's OS
					continue
				}
			}
			h := cmd.Help(s.menu)
			d := []string{cmd.String(), h.Description(), h.Usage()}
			data = append(data, d)
		}
	}

	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeader([]string{"Command", "Description", "Usage"})
	table.AppendBulk(data)
	table.Render()

	version := color.YellowString("Merlin C2 Server (version %s)", merlin.Version)
	wiki := color.BlueString("Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html")
	msg := message.NewUserMessage(message.Plain, fmt.Sprintf("%s\n%s\n\n%s", version, tableString, wiki))
	s.messageRepo.Add(msg)
}

// completer gets a list of all commands in the repository and creates the tab completion functions for all commands
// that are available for the current menu
func (s *Service) completer() *readline.PrefixCompleter {
	var completers []readline.PrefixCompleterInterface

	cmds := s.commandRepo.GetAll()
	for _, cmd := range cmds {
		if cmd.Menu(s.menu) {
			var c readline.PrefixCompleterInterface
			switch s.menu {
			case menu.AGENT:
				c = cmd.Completer(s.menu, s.agent)
				if c != nil {
					// If the Agent's OS is ALL or UNDEFINED, add the completer
					// If the command's OS is ALL or LOCAL, add the completer
					if cmd.OS() == merlinOS.ALL || cmd.OS() == merlinOS.LOCAL || s.agentOS == merlinOS.UNDEFINED || s.agentOS == merlinOS.ALL {
						completers = append(completers, c)
						continue
					}
					// If the Agent's OS is defined, check if the command is valid for the Agent's OS
					if s.agentOS == cmd.OS() {
						completers = append(completers, c)
					}
				}
			case menu.LISTENER, menu.LISTENERS, menu.LISTENERSETUP:
				c = cmd.Completer(s.menu, s.listener)
				if c != nil {
					completers = append(completers, c)
				}
			case menu.MAIN:
				c = cmd.Completer(s.menu, uuid.Nil)
				if c != nil {
					completers = append(completers, c)
				}
			case menu.MODULE, menu.MODULES:
				c = cmd.Completer(s.menu, s.module)
				if c != nil {
					completers = append(completers, c)
				}
			default:
				msg := message.NewErrorMessage(fmt.Errorf("pkg/cli/services/cli.completer(): unhandled menu %s", s.menu))
				s.messageRepo.Add(msg)
			}
		}
	}
	return readline.NewPrefixCompleter(completers...)
}

// queueCommand processes the 'queue' command that results in calling handle() multiple times, once for each Agent in the group
func (s *Service) queueCommand(input string) {
	// 0. queue, 1. AgentID/GroupID, 2. command, 3. args
	command := strings.Split(input, " ")

	// Get the queue command from the repository
	cmd, err := s.commandRepo.Get(s.menu, command[0])
	if err != nil {
		var msg *message.UserMessage
		switch err {
		case repository.ErrCommandNotFound:
			msg = message.NewUserMessage(message.Warn, fmt.Sprintf("'%s' is not a valid command", command[0]))
		case repository.ErrCommandNotInMenu:
			msg = message.NewUserMessage(message.Warn, fmt.Sprintf("'%s' is not a valid command for this '%s' menu", command[0], s.menu.String()))
		default:
			msg = message.NewUserMessage(message.Warn, fmt.Sprintf("%s.handle(): %s", pkg, err))
		}
		s.messageRepo.Add(msg)
		return
	}

	// Check for help and desired argument counts
	resp := cmd.Do(s.menu, uuid.Nil, input)
	if resp.Message != nil {
		s.messageRepo.Add(resp.Message)
		return
	}

	// Ensure the original menu context is preserved and restored to include the completer
	originalMenu := s.menu
	defer func(m menu.Menu) {
		s.menu = m
		service.prompt.Config.AutoComplete = s.completer()
	}(originalMenu)

	// See if the first argument is a UUID
	id, err := uuid.FromString(command[1])
	if err == nil {
		s.Lock()
		s.menu = menu.AGENT
		s.agent = id
		s.handle(strings.Join(command[2:], " "))
		s.agent = uuid.Nil
		s.menu = menu.MAIN
		s.Unlock()
		return
	}

	var found bool
	var group string

	// See if the first argument is a group
	for _, group = range rpc.Groups() {
		if group == command[1] {
			found = true
			break
		}
	}

	// Could not find a group with the provided name
	if !found {
		msg := message.NewErrorMessage(fmt.Errorf("couldn't find an Agent or group with the name '%s'", command[1]))
		s.messageRepo.Add(msg)
		return
	}

	// Run the command for each agent in the group
	for _, agent := range rpc.GroupList(group) {
		// We know it's a valid UUID because it's already in a group
		id, err = uuid.FromString(agent)
		if err != nil {
			msg := message.NewErrorMessage(fmt.Errorf("error parsing UUID from string: %s", err))
			s.messageRepo.Add(msg)
			return
		}
		s.Lock()
		s.menu = menu.AGENT
		s.agent = id
		// 0. queue
		// 1. agent or group ID
		// 2. command to run
		s.handle(strings.Join(command[2:], " "))
		s.menu = menu.MAIN
		s.agent = uuid.Nil
		s.Unlock()
	}
	return
}

// displayUserMessages is an infinite loop as a go routine that gets UserMessage structures from the repository and
// displays them on STDOUT in the CLI
func (s *Service) displayUserMessages() {
	go func() {
		for {
			m := s.messageRepo.Get()
			core.STDOUT.Lock()
			switch m.Level() {
			case message.Info:
				msg := fmt.Sprintf("[i] %s %s", m.Timestamp().UTC().Format(time.RFC3339), m.Message())
				fmt.Println(color.CyanString("\n%s", msg))
				slog.Info(msg)
			case message.Note:
				msg := fmt.Sprintf("[-] %s %s", m.Timestamp().UTC().Format(time.RFC3339), m.Message())
				fmt.Println(color.YellowString("\n%s", msg))
				slog.Info(msg)
			case message.Warn:
				msg := fmt.Sprintf("[!] %s %s", m.Timestamp().UTC().Format(time.RFC3339), m.Message())
				fmt.Println(color.RedString("\n%s", msg))
				slog.Warn(msg)
			case message.Debug:
				msg := fmt.Sprintf("[DEBUG] %s %s", m.Timestamp().UTC().Format(time.RFC3339), m.Message())
				if core.Debug {
					fmt.Println(color.RedString("\n%s", msg))
				}
				slog.Debug(msg)
			case message.Success:
				msg := fmt.Sprintf("[+] %s %s", m.Timestamp().UTC().Format(time.RFC3339), m.Message())
				fmt.Println(color.GreenString("\n%s", msg))
				slog.Info(msg)
			case message.Plain:
				fmt.Printf("%s\n", m.Message())
				slog.Info(m.Message())
			default:
				msg := fmt.Sprintf("[_-_] %s Invalid message level: %d %s", m.Timestamp().UTC().Format(time.RFC3339), m.Level(), m.Message())
				fmt.Println(color.RedString("\n%s", msg))
				slog.Warn(msg)
			}
			core.STDOUT.Unlock()
		}
	}()
}

// confirm reads in a string and returns true if the string is y or yes but does not provide the prompt question
func (s *Service) confirm(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	msg := message.NewUserMessage(message.Plain, color.RedString(fmt.Sprintf("%s [yes/NO]: ", question)))
	s.messageRepo.Add(msg)

	response, err := reader.ReadString('\n')
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error reading the input: %s", err))
		s.messageRepo.Add(msg)
	}

	response = strings.ToLower(response)
	response = strings.Trim(response, "\r\n")
	yes := []string{"y", "yes", "-y", "-Y"}

	for _, match := range yes {
		if response == match {
			return true
		}
	}
	return false
}

// osSignalHandler catches SIGINT and SIGTERM signals to prevent accidentally quitting the server when Ctrl-C is pressed
func (s *Service) osSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		if s.confirm("Are you sure you want to exit?") {
			slog.Info("[!]Quitting...")
			os.Exit(0)
		}
	}()
}

// logging sets up logging for the CLI
func logging() {
	var logFile *os.File
	logFileDir, err := os.Getwd()
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error getting the current working directory: %s", err))
	}
	logFilePath := filepath.Join(core.CurrentDir, "merlinClientLog.txt")
	_, err = os.Stat(logFilePath)
	// If the log file doesn't exist, create it
	if os.IsNotExist(err) {
		err = os.MkdirAll(logFileDir, 0750)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error creating the log directory at %s: %s", logFileDir, err))
		}
		logFile, err = os.Create(logFilePath)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error creating the log file at %s: %s", logFilePath, err))
		}
		// Change the file's permissions
		err = os.Chmod(logFile.Name(), 0600)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error changing the log file permissions: %s", err))
		}
	} else if err != nil {
		log.Fatal(fmt.Sprintf("there was an getting information for the log file at %s: %s", logFilePath, err))
	}

	// File already exists, open it for appending
	logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error opening the log file at %s: %s", logFilePath, err))
	}

	// Set up the program's logging
	//mw := io.MultiWriter(os.Stdout, logFile)

	opts := &slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelInfo,
		ReplaceAttr: nil,
	}
	logger := slog.New(slog.NewJSONHandler(logFile, opts))
	slog.SetDefault(logger)
	log.SetFlags(log.LstdFlags | log.LUTC | log.Llongfile)
}
