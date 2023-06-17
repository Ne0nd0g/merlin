package cli

import (
	"fmt"
	merlin "github.com/Ne0nd0g/merlin/pkg"
	"github.com/Ne0nd0g/merlin/pkg/api/messages"
	moduleAPI "github.com/Ne0nd0g/merlin/pkg/api/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/core"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
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
	id          uuid.UUID
	commandRepo commands.Repository
	prompt      *readline.Instance
	menu        menu.Menu
	module      modules.Module
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
			commandRepo: withMemoryCommandRepository(),
			menu:        menu.MAIN,
			prompt:      prompt,
			id:          uuid.NewV4(),
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
	var cmd commands.Command
	switch strings.ToLower(command[0]) {
	case "help", "--help", "-h", "?":
		s.help()
		return
	case "listeners":
		s.menu = menu.LISTENER
		s.prompt.SetPrompt("\033[31mMerlin[\033[32mlisteners\033[31m]»\033[0m ")
		s.prompt.Config.AutoComplete = s.completer()
		return
	case "use":
		s.handleModuleMenu(input)
	case "version":
		fmt.Println("HERE VERSION")
		core.MessageChannel <- messages.UserMessage{
			Level:   messages.Plain,
			Message: color.BlueString("Merlin version: %s\n", merlin.Version),
			Time:    time.Now().UTC(),
			Error:   false,
		}
		return
	default:
		var err error
		// Get the command from the repository
		cmd, err = s.commandRepo.Get(s.menu, command[0])
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
	}

	// Send the original input so the command can decide how to parse it
	core.MessageChannel <- cmd.Do(input)
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
	table.SetHeader([]string{"Command", "Description", "Options"})

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
			completers = append(completers, cmd.Completer())
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
