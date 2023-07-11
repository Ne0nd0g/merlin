package cli

import (
	"fmt"
	merlin "github.com/Ne0nd0g/merlin/pkg"
	agentAPI "github.com/Ne0nd0g/merlin/pkg/api/agents"
	listenerAPI "github.com/Ne0nd0g/merlin/pkg/api/listeners"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	listenerEntity "github.com/Ne0nd0g/merlin/pkg/cli/entity/listener"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener"
	lmemory "github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	"github.com/Ne0nd0g/merlin/pkg/modules"
	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Service struct {
	id           uuid.UUID
	agent        uuid.UUID
	listener     uuid.UUID
	commandRepo  commands.Repository
	listenerRepo listener.Repository
	prompt       *readline.Instance
	menu         menu.Menu
	module       modules.Module
	sync.Mutex
}

var service *Service
var pkg = "pkg/cli/services/cli"

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
		// Start UserMessage channel
		osSignalHandler()
		printUserMessage()
		service.registerMessageChannel()
		service.getUserMessages()
	}
	return service
}

func withMemoryCommandRepository() commands.Repository {
	return memory.NewRepository()
}

func withMemoryListenerRepository() listener.Repository {
	return lmemory.NewRepository()
}

func (s *Service) Run() {
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
				s.handleMainMenu(line)
			default:
				s.handleMainMenu(line)
			}
		}
	}
}

// handleMainMenu handles commands issued at the main menu
func (s *Service) handleMainMenu(input string) {
	if len(input) <= 0 {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("%s.handleMainMenu(): no input provided", pkg),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	}

	command := strings.Split(input, " ")
	if len(command) <= 0 {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("%s.handleMainMenu(): no command provided", pkg),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	}

	// Commands
	// agent
	// clear
	// group
	// interact
	// jobs
	// queue
	// remove
	// sessions
	// set
	// socks
	// use
	switch strings.ToLower(command[0]) {
	case "agent":
		if len(command) > 1 {
			switch strings.ToLower(command[1]) {
			case "interact":
				// Must do this here to change the prompt
				if len(command) > 2 {
					s.interactAgent(command[2])
					return
				}
			}
		}
	case "exit":
		// The exit command is reserved to instruct an Agent to exit
		// From the main menu, swap exit for quit
		command[0] = "quit"
	case "help", "--help", "-h", "?":
		s.help()
		return
	case "interact":
		if len(command) > 1 {
			if command[1] != "-h" && command[1] != "--help" && command[1] != "?" && command[1] != "help" {
				s.interactAgent(command[1])
				return
			}
		}
	case "listeners":
		s.menu = menu.LISTENER
		s.prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
		s.prompt.Config.AutoComplete = s.completer()
		return
	case "main":
		s.menu = menu.MAIN
		s.prompt.SetPrompt("\u001B[31mMerlin»\u001B[0m ")
		s.prompt.Config.AutoComplete = s.completer()
		return
	case "queue":
		// Must process queue command here because it subsequently calls other commands
		if len(command) > 2 {
			// Check for uuid match
			id, err := uuid.FromString(command[1])
			if err == nil {
				s.id = id
				s.handleMainMenu(strings.Join(command[2:], " "))
				s.id = uuid.Nil
			} else {
				found := false
				// Check for a group name match
				for _, group := range agentAPI.GroupListNames() {
					if group == command[1] {
						found = true
						for _, agent := range agentAPI.GroupList(group) {
							// We know it's a valid UUID because it's already in a group
							id, err := uuid.FromString(agent)
							if err != nil {
								core.MessageChannel <- messages.UserMessage{
									Level:   messages.Warn,
									Message: fmt.Sprintf("error parsing UUID from string: %s", err),
									Time:    time.Now().UTC(),
									Error:   false,
								}
								return
							}
							s.id = id
							s.handleMainMenu(strings.Join(command[2:], " "))
							s.id = uuid.Nil
						}
					}
				}
				// Nothing found
				if !found {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: fmt.Sprintf("Couldn't find an Agent or group with the name '%s'", command[1]),
						Time:    time.Now().UTC(),
						Error:   true,
					}
				}
				return
			}
		}
	case "use":
		switch s.menu {
		case menu.MAIN:
			s.handleModuleMenu(input)
		case menu.LISTENER:
			if len(command) > 1 {
				types := listenerAPI.GetListenerTypes()
				for _, t := range types {
					if strings.ToLower(t) == strings.ToLower(command[1]) {
						options, err := listenerAPI.GetDefaultOptions(t)
						if err != nil {
							core.MessageChannel <- messages.UserMessage{
								Level:   messages.Warn,
								Message: fmt.Sprintf("error getting default listener options: %s", err),
								Time:    time.Now().UTC(),
								Error:   false,
							}
							return
						}
						l := listenerEntity.NewListener(t, options)
						s.listenerRepo.Add(l)
						s.listener = l.ID()
						s.menu = menu.LISTENERSETUP
						s.prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + t + "\033[31m]»\033[0m ")
						s.prompt.Config.AutoComplete = s.completer()
						return
					}
				}
			}
		}
		return
	case "version":
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Plain,
			Message: color.BlueString("Merlin version: %s\n", merlin.Version),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	default:
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
		case memory.ErrCommandNotFound:
			msg.Message = fmt.Sprintf("'%s' is not a valid command", command[0])
		case memory.ErrCommandNotInMenu:
			msg.Message = fmt.Sprintf("'%s' is not a valid command for this '%s' menu", command[0], s.menu.String())
		default:
			msg.Message = fmt.Sprintf("%s.handleMainMenu(): %s", pkg, err)
		}
		core.MessageChannel <- msg
		return
	}

	// Send the original input so the command can decide how to parse it
	var message messages.UserMessage
	switch s.menu {
	case menu.LISTENERSETUP:
		if s.listener != uuid.Nil {
			message = cmd.DoID(s.listener, input)
			if message.Error {
				break
			}
			switch strings.ToLower(command[0]) {
			case "run", "start":
				// Need to process here to change the CLI prompt
				l, err := s.listenerRepo.Get(s.listener)
				if err != nil {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: fmt.Sprintf("there was an error getting the listener for ID %s: %s", s.listener, err),
						Time:    time.Now().UTC(),
						Error:   true,
					}
				}
				if _, ok := l.Options()["Name"]; !ok {
					core.MessageChannel <- messages.UserMessage{
						Level:   messages.Warn,
						Message: fmt.Sprintf("the 'name' key was not found in the listener options for %s", s.listener),
						Time:    time.Now().UTC(),
						Error:   true,
					}
					break
				}
				s.menu = menu.LISTENER
				s.prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m][\033[33m" + l.Options()["Name"] + "\033[31m]»\033[0m ")
				s.prompt.Config.AutoComplete = s.completer()
			}
		} else {
			message = cmd.Do(input)
		}
	default:
		if s.agent != uuid.Nil {
			message = cmd.DoID(s.agent, input)
		} else {
			message = cmd.Do(input)
		}
	}

	if message.Message != "" {
		core.MessageChannel <- message
	}
	return
}

func (s *Service) handleModuleMenu(input string) (err error) {
	if len(input) <= 0 {
		return fmt.Errorf("%s.handleModuleMenu(): no input provided", pkg)
	}

	cmd := strings.Split(input, " ")
	if len(cmd) <= 1 {
		return fmt.Errorf("%s.handleModuleMenu(): no command provided", pkg)
	}

	switch cmd[1] {
	// For when "use module <module> is called from the main menu
	case "module":
		if len(cmd) > 2 {
			if len(cmd) > 0 {
				mPath := path.Join(core.CurrentDir, "data", "modules", cmd[2]+".json")
				um, m := moduleAPI.GetModule(mPath)
				if um.Error {
					core.MessageChannel <- um
					return
				}
				if m.Name != "" {
					s.module = m
					s.menu = menu.MODULE
					core.Prompt.SetPrompt("\033[31mMerlin[\033[32mmodule\033[31m][\033[33m" + s.module.Name + "\033[31m]»\033[0m ")
					core.Prompt.Config.AutoComplete = s.completer()
				}
			}
		} else {
			core.MessageChannel <- messages.UserMessage{
				Level:   messages.Warn,
				Message: "Invalid module",
				Time:    time.Now().UTC(),
				Error:   false,
			}
		}
	case "":
	default:
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Note,
			Message: "Invalid 'use' command",
			Time:    time.Now().UTC(),
			Error:   false,
		}
	}
	return
}

func (s *Service) help() {
	var data [][]string
	// Table of command, description, usage
	cmds := s.commandRepo.GetAll()
	for _, cmd := range cmds {
		if cmd.Menu(s.menu) {
			d := []string{cmd.String(), cmd.Description(), cmd.Usage()}
			data = append(data, d)
		}
	}

	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Plain,
		Message: color.YellowString("Merlin C2 Server (version %s)\n", merlin.Version),
		Time:    time.Now().UTC(),
		Error:   false,
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetCaption(true, "Main Menu Help")
	table.SetHeader([]string{"Command", "Description", "Usage"})

	table.AppendBulk(data)
	// TODO lock STDOUT so nothing else writes to it
	fmt.Println()
	table.Render()
	fmt.Println()
	core.MessageChannel <- messages.UserMessage{
		Level:   messages.Info,
		Message: "Visit the wiki for additional information https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html",
		Time:    time.Now().UTC(),
		Error:   false,
	}
}

func (s *Service) exit(cmd []string) {
	if len(cmd) > 1 {
		if strings.ToLower(cmd[1]) == "-y" {
			core.Exit()
		}
	}
	if core.Confirm("Are you sure you want to quit the server?") {
		core.Exit()
	}
}

func (s *Service) completer() *readline.PrefixCompleter {
	var completers []readline.PrefixCompleterInterface

	cmds := s.commandRepo.GetAll()
	for _, cmd := range cmds {
		if cmd.Menu(s.menu) {
			var c readline.PrefixCompleterInterface
			switch s.menu {
			case menu.LISTENERSETUP:
				c, _ = cmd.Completer(s.listener)
			default:
				c, _ = cmd.Completer(s.agent)
			}
			completers = append(completers, c)
		}
	}
	return readline.NewPrefixCompleter(completers...)
}

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

func (s *Service) getUserMessages() {
	go func() {
		for {
			core.MessageChannel <- messages.GetMessageForClient(s.id)
		}
	}()
}

// printUserMessage is used to print all messages to STDOUT for command line clients
func printUserMessage() {
	go func() {
		for {
			m := <-core.MessageChannel
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

// interactAgent is used to issue commands to a specific agent
func (s *Service) interactAgent(id string) {
	agentID, err := uuid.FromString(id)
	if err != nil {
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Warn,
			Message: fmt.Sprintf("There was an error interacting with agent %s", id),
			Time:    time.Now().UTC(),
			Error:   true,
		}
	} else {
		// TODO Validate the agent exists
		s.agent = agentID
		s.menu = menu.AGENT
		s.prompt.SetPrompt(fmt.Sprintf("\033[31mMerlin[\033[32magent\033[31m][\033[33m%s\033[31m]»\033[0m ", agentID))
	}
}
