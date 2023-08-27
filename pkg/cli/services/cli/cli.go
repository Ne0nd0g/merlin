package cli

import (
	// Standard
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
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
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	"github.com/Ne0nd0g/merlin/pkg/logging"

	// Internal - CLI
	"github.com/Ne0nd0g/merlin/pkg/cli/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/repository"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	merlinOS "github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener"
	lmemory "github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
)

// Service is a structure for the CLI service that holds the state of the CLI
type Service struct {
	id           uuid.UUID           // id is the unique identifier for the CLI service
	agent        uuid.UUID           // agent is the unique identifier for the Agent the CLI is interacting with
	agentOS      merlinOS.OS         // agentOS is the operating system of the Agent the CLI is interacting with
	listener     uuid.UUID           // listener is the unique identifier for the Listener the CLI is interacting with
	commandRepo  commands.Repository // commandRepo is the repository of commands the CLI can execute
	listenerRepo listener.Repository // listenerRepo is the repository of listeners the CLI can interact with
	prompt       *readline.Instance  // prompt is the visual string displayed to the user as well as other components such as tab completion
	menu         menu.Menu           // menu is the current menu the CLI is in
	module       uuid.UUID           // module is the unique identifier for the Module the CLI is interacting with
	sync.Mutex
}

// services in the instantiated Service structure for this CLI service
var service *Service

// pkg is a string containing the package name for this file used with error messages
var pkg = "pkg/cli/services/cli"

// NewCLIService is a factory that creates a new CLI service
func NewCLIService() *Service {
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
			log.Fatalf("There was an error creating the CLI prompt: %s", err.Error())
		}
		service = &Service{
			commandRepo:  withMemoryCommandRepository(),
			listenerRepo: withMemoryListenerRepository(),
			menu:         menu.MAIN,
			prompt:       prompt,
			id:           uuid.NewV4(),
			agent:        uuid.Nil,
			listener:     uuid.Nil,
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

// Run is the main entry point for the CLI service called by the main package
func (s *Service) Run() {
	logging.Server(fmt.Sprintf("Starting Merlin version: %s, build: %s, client ID: %s", merlin.Version, merlin.Build, s.id))

	// Start handlers and go routines
	osSignalHandler()
	printUserMessage()
	s.registerMessageChannel()
	s.getUserMessages()

	// Display the Merlin banner
	display := color.BlueString(banner.MerlinBanner1)
	display += color.BlueString(fmt.Sprintf("\n\t\t\tVersion: %s\n", merlin.Version))
	display += color.BlueString(fmt.Sprintf("\t\t\tBuild: %s\n", merlin.Build))
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: display,
	}

	// Start infinite loop to process command line input
	for {
		// Read command line input
		line, err := s.prompt.Readline()

		// Handle Ctrl+C
		if err == readline.ErrInterrupt {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		} else if err == io.EOF {
			if core.Confirm("Are you sure you want to quit the server?") {
				core.Exit()
			}
		}

		line = strings.TrimSpace(line)
		cmd, err := shellwords.Parse(line)
		if err != nil {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing command line arguments:\r\n%s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
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
	if len(input) <= 0 {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("%s.handle(): no input provided", pkg),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	}

	command := strings.Split(input, " ")
	if len(command) <= 0 {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("%s.handle(): no command provided", pkg),
			Time:    time.Now().UTC(),
			Error:   false,
		}
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
		msg := messages.UserMessage{
			Level: messages.Warn,
			Time:  time.Now().UTC(),
			Error: false,
		}
		switch err {
		case repository.ErrCommandNotFound:
			msg.Message = fmt.Sprintf("'%s' is not a valid command", command[0])
		case repository.ErrCommandNotInMenu:
			msg.Message = fmt.Sprintf("'%s' is not a valid command for this '%s' menu", command[0], s.menu.String())
		default:
			msg.Message = fmt.Sprintf("%s.handle(): %s", pkg, err)
		}
		core.MessageChannel <- msg
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
			var agentOS string
			_, agentOS, err = agentAPI.GetAgent(s.agent)
			if err != nil {
				if core.Debug {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: fmt.Sprintf("there was an error making the GetAgent API call: %s", err),
						Time:    time.Now().UTC(),
						Error:   false,
					}
					return
				}
			}
			o := merlinOS.FromString(agentOS)
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
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("The '%s' command is for the %s operating system and not supported for this agent's operating system (%s)", cmd, cmd.OS(), s.agentOS),
				Time:    time.Now().UTC(),
				Error:   false,
			}
			return
		}
	}

	// Send the original input so the command can decide how to parse it
	resp := cmd.Do(s.menu, id, input)
	if resp.Message != nil {
		if resp.Message.Error {
			core.MessageChannel <- *resp.Message
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
		core.MessageChannel <- *resp.Message
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
						_, agentOS, err := agentAPI.GetAgent(s.agent)
						if err != nil {
							if core.Debug {
								core.MessageChannel <- messages.UserMessage{
									Level: messages.Warn,
									Message: fmt.Sprintf("there was an error trying to update the Agent's OS when"+
										" making the GetAgent API call to filter the commands displayed in help "+
										"menu: %s", err),
									Time:  time.Now().UTC(),
									Error: false,
								}
							}
						}
						o := merlinOS.FromString(agentOS)
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
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: fmt.Sprintf("%s\n%s\n\n%s", version, tableString, wiki),
		Time:    time.Now().UTC(),
		Error:   false,
	}
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
				core.MessageChannel <- messages.ErrorMessage(fmt.Sprintf("pkg/cli/services/cli.completer(): unhandled menu %s", s.menu))
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
		msg := messages.UserMessage{
			Level: messages.Warn,
			Time:  time.Now().UTC(),
			Error: false,
		}
		switch err {
		case repository.ErrCommandNotFound:
			msg.Message = fmt.Sprintf("'%s' is not a valid command", command[0])
		case repository.ErrCommandNotInMenu:
			msg.Message = fmt.Sprintf("'%s' is not a valid command for this '%s' menu", command[0], s.menu.String())
		default:
			msg.Message = fmt.Sprintf("%s.handle(): %s", pkg, err)
		}
		core.MessageChannel <- msg
		return
	}

	// Check for help and desired argument counts
	resp := cmd.Do(s.menu, uuid.Nil, input)
	if resp.Message != nil {
		core.MessageChannel <- *resp.Message
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
	for _, group = range agentAPI.GroupListNames() {
		if group == command[1] {
			found = true
			break
		}
	}

	// Could not find a group with the provided name
	if !found {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("Couldn't find an Agent or group with the name '%s'", command[1]),
			Time:    time.Now().UTC(),
			Error:   true,
		}
		return
	}

	// Run the command for each agent in the group
	for _, agent := range agentAPI.GroupList(group) {
		// We know it's a valid UUID because it's already in a group
		id, err = uuid.FromString(agent)
		if err != nil {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: fmt.Sprintf("error parsing UUID from string: %s", err),
				Time:    time.Now().UTC(),
				Error:   false,
			}
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

// registerMessageChannel registers as a message channel to receive messages from the server
func (s *Service) registerMessageChannel() {
	um := messages.Register(s.id)
	if um.Error {
		core.MessageChannel <- um
		return
	}
	if core.Debug {
		core.MessageChannel <- um
	}
}

// getUserMessages is an infinite loop as a go routine that listens for messages from the server and adds them to the
// local message channel
func (s *Service) getUserMessages() {
	go func() {
		for {
			core.MessageChannel <- messages.GetMessageForClient(s.id)
		}
	}()
}

// printUserMessage is an infinite loop as go routine that receives messages and prints them to STDOUT
func printUserMessage() {
	go func() {
		for {
			m := <-core.MessageChannel
			core.STDOUT.Lock()
			switch m.Level {
			case messages.Info:
				fmt.Println(color.CyanString("\n[i] %s", m.Message))
			case messages.Note:
				fmt.Println(color.YellowString("\n[-] %s", m.Message))
			case messages.Warn:
				fmt.Println(color.RedString("\n[!] %s", m.Message))
			case messages.Debug:
				if core.Debug {
					fmt.Println(color.RedString("\n[DEBUG] %s", m.Message))
				}
			case messages.Success:
				fmt.Println(color.GreenString("\n[+] %s", m.Message))
			case messages.Plain:
				fmt.Println("\n" + m.Message)
			default:
				fmt.Println(color.RedString("\n[_-_] Invalid message level: %d\r\n%s", m.Level, m.Message))
			}
			core.STDOUT.Unlock()
		}
	}()
}

// osSignalHandler catches SIGINT and SIGTERM signals to prevent accidentally quitting the server when Ctrl-C is pressed
func osSignalHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		if core.Confirm("Are you sure you want to exit?") {
			core.Exit()
		}
	}()
}
