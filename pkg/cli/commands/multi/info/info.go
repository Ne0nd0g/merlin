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

package info

import (
	// Standard
	"fmt"
	"strconv"
	"strings"
	"time"

	// 3rd Party
	"github.com/chzyer/readline"
	"github.com/olekukonko/tablewriter"
	uuid "github.com/satori/go.uuid"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/completer"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/help"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/os"
	"github.com/Ne0nd0g/merlin/pkg/cli/listener/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	moduleMemory "github.com/Ne0nd0g/merlin/pkg/cli/module/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/services/rpc"
)

// Command is an aggregate structure for a command executed on the command line interface
type Command struct {
	name   string                  // name is the name of the command
	help   map[menu.Menu]help.Help // help is the Help structure for the command
	menus  []menu.Menu             // menu is the Menu the command can be used in
	native bool                    // native is true if the command is executed by an Agent using only Golang native code
	os     os.OS                   // os is the supported operating system the Agent command can be executed on
}

// NewCommand is a factory that builds and returns a Command structure that implements the Command interface
func NewCommand() *Command {
	var cmd Command
	cmd.name = "info"
	cmd.menus = []menu.Menu{menu.AGENT, menu.LISTENER, menu.LISTENERS, menu.LISTENERSETUP, menu.MODULE}
	cmd.os = os.LOCAL
	cmd.help = make(map[menu.Menu]help.Help)

	// Help for the Agent menu
	agentDescription := "Display information about the Agent"
	agentExample := "Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» info\n\n" +
		"\t  ID                             | c1090dbc-f2f7-4d90-a241-86e0c0217786\n" +
		"\t  Alive                          | true\n" +
		"\t  Status                         | Active\n" +
		"\t  Platform                       | linux/amd64\n" +
		"\t  User Name                      | rastley\n" +
		"\t  User GUID                      | 1000\n" +
		"\t  Integrity Level                | 3\n" +
		"\t  Hostname                       | ubuntu\n" +
		"\t  Process Name                   | /tmp/go-build799148624/b001/exe/main\n" +
		"\t  Process ID                     | 200769\n" +
		"\t  IP                             | 127.0.0.1/8 ::1/128\n" +
		"\t                                 | 192.168.1.2/24\n" +
		"\t                                 | fe80::b7bb:3953:682e:cb7f/64\n" +
		"\t  Initial Check In               | 2021-08-02T23:56:10Z\n" +
		"\t  Last Check In                  | 2021-08-03T00:18:55Z (0:00:05\n" +
		"\t                                 | ago)\n" +
		"\t  Linked Agents                  | []\n" +
		"\t  Groups                         |\n" +
		"\t  Note                           |\n" +
		"\t                                 |\n" +
		"\t  Agent Version                  | 1.0.2\n" +
		"\t  Agent Build                    | nonRelease\n" +
		"\t  Agent Wait Time                | 10s\n" +
		"\t  Agent Wait Time Skew           | 3000\n" +
		"\t  Agent Message Padding Max      | 4096\n" +
		"\t  Agent Max Retries              | 7\n" +
		"\t  Agent Failed Check In          | 0\n" +
		"\t  Agent Kill Date                | 1970-01-01T00:00:00Z\n" +
		"\t  Agent Communication Protocol   | h2\n" +
		"\t  Agent JA3 TLS Client Signature |"
	agentNotes := "\n\tStatus - The agent’s current communication status of either active, delayed, or dead\n" +
		"\tID - The agent’s unique identifier that is generated on execution\n" +
		"\tAlive - Whether or not the agent is currently alive. Determined by last checkin time and max failed logins\n" +
		"\tStatus - The agent’s current communication status of either active, delayed, or dead\n" +
		"\tPlatform - The operating system and architecture the agent is running on\n" +
		"\tUser Name - The user name the agent is currently running as\n" +
		"\tUser GUID - The unique identifier for the user the agent is currently running as\n" +
		"\tIntegrity Level - The integrity level of the user the agent is currently running as with.\n" +
		"\t\t0: untrusted integrity for Windows\n" +
		"\t\t1: low integrity for Windows\n" +
		"\t\t2: standard user for linux or medium integrity for Windows\n" +
		"\t\t3: member of sudo group for linux or high integrity for Windows\n" +
		"\t\t4: root or NT AUTHORITY\\SYSTEM\n" +
		"\tHostname - The name of the compromised host where the agent is currently running\n" +
		"\tProcess Name - The name of the process the agent is currently running in\n" +
		"\tProcess ID - The numerical Process ID (PID) that the agent is currently running in\n" +
		"\tIP - A list of interface IP addresses for where the agent is currently running\n" +
		"\tInitial Check In - The date and time the agent first connected to the server\n" +
		"\tLast Check In - The date and time the agent last connected to the server followed by the relative amount of time in parenthesis\n" +
		"\tLinked Agents - Child peer-to-peer Agent connections\n" +
		"\tGroups - Any server-side groups the agent is a member of\n" +
		"\tNote - Any operator generated notes about the agent\n" +
		"\tAgent Version - The version number of the running agent\n" +
		"\tAgent Build - A hash of the git commit the agent was built from\n" +
		"\tAgent Wait Time - The amount of time the agent waits, or sleeps, between checkins\n" +
		"\tAgent Wait Time Skew - The amount of skew multiplied to the agent wait time\n" +
		"\tAgent Message Padding Max - The maximum amount of random data appended to every message to/from the agent\n" +
		"\tAgent Max Retries - The maximum amount of times an agent can fail to check in before it quits running\n" +
		"\tAgent Failed Check In - The total number of failed check in attempts\n" +
		"\tAgent Kill Date - The date the agent will quit running. 1970-01-01T00:00:00Z signifies that the kill date is not set\n" +
		"\tAgent Communication Protocol - The protocol the agent is currently communicating over\n" +
		"\tAgent JA3 TLS Client Signature - The JA3 client signature. If empty then the default Merlin signature is being used"
	agentUsage := "info"
	cmd.help[menu.AGENT] = help.NewHelp(agentDescription, agentExample, agentNotes, agentUsage)

	// Help for the Listeners menu
	listenersDescription := "Display the Listener template configurable options and their current value."
	listenersUsage := "info"
	listenersExample := "Merlin[listeners]» use https\n" +
		"\tMerlin[listeners][https]» info\n" +
		"\t+-------------+------------------+\n" +
		"\t|    NAME     |      VALUE       |\n" +
		"\t+-------------+------------------+\n" +
		"\t| PSK         | merlin           |\n" +
		"\t+-------------+------------------+\n" +
		"\t| Interface   | 127.0.0.1        |\n" +
		"\t+-------------+------------------+\n" +
		"\t| Port        | 443              |\n" +
		"\t+-------------+------------------+\n" +
		"\t| URLS        | /                |\n" +
		"\t+-------------+------------------+\n" +
		"\t| X509Cert    |                  |\n" +
		"\t+-------------+------------------+\n" +
		"\t| X509Key     |                  |\n" +
		"\t+-------------+------------------+\n" +
		"\t| Name        | Default          |\n" +
		"\t+-------------+------------------+\n" +
		"\t| Description | Default listener |\n" +
		"\t+-------------+------------------+\n" +
		"\t| Protocol    | https            |\n" +
		"\t+-------------+------------------+\n" +
		"\tMerlin[listeners][https]»"
	listenersNotes := ""
	cmd.help[menu.LISTENER] = help.NewHelp(listenersDescription, listenersExample, listenersNotes, listenersUsage)
	cmd.help[menu.LISTENERS] = help.NewHelp(listenersDescription, listenersExample, listenersNotes, listenersUsage)
	cmd.help[menu.LISTENERSETUP] = help.NewHelp(listenersDescription, listenersExample, listenersNotes, listenersUsage)

	// Help for the Modules menu
	modDescription := "Show information about the module"
	modExample := "Merlin[modules][linux/x64/bash/exec/bash]» info\n" +
		"\n" +
		"\t[i] \n" +
		"\t'BASH' module information\n\n" +
		"\tPlatform:\n" +
		"\t\tlinux\\x64\\bash\n" +
		"\tModule Authors:\n" +
		"\t\tRussel Van Tuyl (@Ne0nd0g)\n" +
		"\tCredits:\n" +
		"\tDescription:\n" +
		"\t\tExecute a command in a BASH terminal. Useful to run a single command across all agents\n" +
		"\tOptions:\n\n" +
		"\t\t   NAME   |                VALUE                 | REQUIRED |          DESCRIPTION            \n" +
		"\t\t+---------+--------------------------------------+----------+--------------------------------+\n" +
		"\t\t  Agent   | 00000000-0000-0000-0000-000000000000 | true     | Agent on which to run module    \n" +
		"\t\t          |                                      |          | BASH                            \n" +
		"\t\t  Command | whoami                               | true     | Command to run in BASH          \n" +
		"\t\t          |                                      |          | terminal                        \n" +
		"\tNotes:\n" +
		"\t\tCommands are run with /bin/bash -c . Use quotes if you want to run multiple commands or shell features such as redirection or pipeline"
	modNotes := ""
	modUsage := "info"
	cmd.help[menu.MODULE] = help.NewHelp(modDescription, modExample, modNotes, modUsage)
	return &cmd
}

// Completer returns the data that is displayed in the CLI for tab completion depending on the menu the command is for
// Errors are not returned to ensure the CLI is not interrupted.
// Errors are logged and can be viewed by enabling debug output in the CLI
func (c *Command) Completer(m menu.Menu, id uuid.UUID) (comp readline.PrefixCompleterInterface) {
	switch m {
	case menu.LISTENERS:
		comp = readline.PcItem(c.name,
			readline.PcItemDynamic(completer.ListenerListCompleter()),
		)
	default:
		comp = readline.PcItem(c.name)
	}
	return
}

// Do executes the command and returns a Response to the caller to facilitate changes in the CLI service
// m, an optional parameter, is the Menu the command was executed from
// id, an optional parameter, used to identify a specific Agent or Listener
// arguments, and optional, parameter, is the full unparsed string entered on the command line to include the
// command itself passed into command for processing
func (c *Command) Do(m menu.Menu, id uuid.UUID, arguments string) (response commands.Response) {
	switch m {
	case menu.AGENT:
		return c.DoAgent(id, arguments)
	case menu.LISTENER:
		return c.DoListener(id, arguments)
	case menu.LISTENERS:
		return c.DoListeners(id, arguments)
	case menu.LISTENERSETUP:
		return c.DoListenerSetup(id, arguments)
	case menu.MODULE:
		return c.DoModule(id, arguments)
	}
	return
}

// DoAgent handles the command for the Agent menu
func (c *Command) DoAgent(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			var h help.Help
			_, ok := c.help[menu.AGENT]
			if !ok {
				response.Message = message.NewErrorMessage(fmt.Errorf("the Help structure for the 'info' command was not found for the '%s' menu", menu.AGENT))
				return
			}
			h = c.help[menu.AGENT]
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	a, err := rpc.GetAgent(id)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("pkg/cli/commands/info.DoAgent(): %s", err))
		return
	}

	// Calculate the last checkin time
	t, err := time.Parse(time.RFC3339, a.StatusCheckin())
	if err != nil {
		// DO NOTHING
	}
	lastTime := time.Since(t)
	lastTimeStr := fmt.Sprintf("%d:%02d:%02d ago",
		int(lastTime.Hours()),
		int(lastTime.Minutes())%60,
		int(lastTime.Seconds())%60)

	build := a.Build()
	host := a.Host()
	comms := a.Comms()
	process := a.Process()
	rows := [][]string{
		{"ID", a.ID().String()},
		{"Alive", fmt.Sprintf("%v", a.Alive())},
		{"Status", a.Status()},
		{"Platform", fmt.Sprintf("%s/%s", host.Platform, host.Architecture)},
		{"User Name", process.UserName},
		{"User GUID", process.UserGUID},
		{"Integrity Level", fmt.Sprintf("%d", process.Integrity)},
		{"Hostname", host.Name},
		{"Process Name", process.Name},
		{"Process ID", fmt.Sprintf("%d", process.ID)},
		{"IP", strings.Join(host.IPs, "\n")},
		{"Initial Check In", a.Initial()},
		{"Last Check In", fmt.Sprintf("%s (%s)", a.StatusCheckin(), lastTimeStr)},
		{"Linked Agents", fmt.Sprintf("%+v", a.Links())},
		{"Groups", fmt.Sprintf("%+v", a.Groups())},
		{"Note", a.Note()},
		{"", ""},
		{"Agent Version", build.Version},
		{"Agent Build", build.Build},
		{"Agent Wait Time", comms.Wait},
		{"Agent Wait Time Skew", strconv.FormatInt(comms.Skew, 10)},
		{"Agent Message Padding Max", fmt.Sprintf("%d", comms.Padding)},
		{"Agent Max Retries", fmt.Sprintf("%d", comms.Retry)},
		{"Agent Failed Check In", fmt.Sprintf("%d", comms.Failed)},
		{"Agent Kill Date", time.Unix(comms.Kill, 0).UTC().Format(time.RFC3339)},
		{"Agent Communication Protocol", comms.Proto},
		{"Agent JA3 TLS Client Signature", comms.JA3},
	}

	// Build the table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.AppendBulk(rows)
	table.Render()

	response.Message = message.NewUserMessage(message.Plain, fmt.Sprintf("\n%s", tableString.String()))

	return
}

// DoListener handles the command for the Listener menu
func (c *Command) DoListener(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			var h help.Help
			_, ok := c.help[menu.LISTENER]
			if !ok {
				response.Message = message.NewErrorMessage(fmt.Errorf("the Help structure for the 'info' command was not found for the '%s' menu", menu.LISTENER))

				return
			}
			h = c.help[menu.LISTENER]
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	msg, options := rpc.ListenerGetConfiguredOptions(id)
	if msg.Error() {
		response.Message = msg
		return
	}

	response.Message = rpc.ListenerStatus(id)
	if response.Message.Error() {
		return
	}

	if options != nil {
		tableString := &strings.Builder{}
		table := tablewriter.NewWriter(tableString)
		table.SetHeader([]string{"Name", "Value"})
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetRowLine(true)
		table.SetBorder(true)

		for k, v := range options {
			table.Append([]string{k, v})
		}
		table.Append([]string{"Status", response.Message.Message()})
		table.Render()

		response.Message = message.NewUserMessage(message.Plain, fmt.Sprintf("\n%s", tableString.String()))
	}
	return
}

// DoListeners handles the command for the Listeners menu
func (c *Command) DoListeners(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Validate at least one argument, in addition to the command, was provided
	if len(args) < 2 {
		response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command requires at least one argument from this menu\ninfo listenerID", c))
		return
	}

	var h help.Help
	_, ok := c.help[menu.LISTENERS]
	if !ok {
		response.Message = message.NewErrorMessage(fmt.Errorf("the Help structure for the 'info' command was not found for the '%s' menu", menu.LISTENERS))
		return
	}
	h = c.help[menu.LISTENERS]

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	// Parse the UUID
	var err error
	id, err = uuid.FromString(args[1])
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("there was an error parsing UUID '%s': %s\n%s", args[1], err, h.Usage()))
		return
	}
	return c.DoListener(id, arguments)
}

// DoListenerSetup handles the command for the ListenerSetup menu
func (c *Command) DoListenerSetup(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			var h help.Help
			_, ok := c.help[menu.LISTENERSETUP]
			if !ok {
				response.Message = message.NewErrorMessage(fmt.Errorf("the Help structure for the 'info' command was not found for the '%s' menu", menu.LISTENERSETUP))
				return
			}
			h = c.help[menu.LISTENERSETUP]
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}
	// Get the options from the listener repository
	repo := memory.NewRepository()
	listener, err := repo.Get(id)
	if err != nil {
		return
	}

	// Set up the table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Name", "Value"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(true)
	table.SetBorder(true)

	for k, v := range listener.Options() {
		table.Append([]string{k, v})
	}
	table.Render()

	response.Message = message.NewUserMessage(message.Plain, fmt.Sprintf("\n%s", tableString.String()))

	return
}

// DoModule handles the command for the Module menu
func (c *Command) DoModule(id uuid.UUID, arguments string) (response commands.Response) {
	// Parse the arguments
	args := strings.Split(arguments, " ")

	// Check for help first
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "help", "-h", "--help", "?", "/?":
			var h help.Help
			_, ok := c.help[menu.MODULE]
			if !ok {
				response.Message = message.NewErrorMessage(fmt.Errorf("the Help structure for the 'info' command was not found for the '%s' menu", menu.MODULE))
				return
			}
			h = c.help[menu.MODULE]
			response.Message = message.NewUserMessage(message.Info, fmt.Sprintf("'%s' command help\nDescription: %s\n\nUsage: %s\n\nExample: %s\n\nNotes: %s", c, h.Description(), h.Usage(), h.Example(), h.Notes()))
			return
		}
	}

	// Get options from the local repository
	repo := moduleMemory.NewRepository()
	m, err := repo.Get(id)
	if err != nil {
		response.Message = message.NewErrorMessage(fmt.Errorf("pkg/cli/commands/info.DoModule(): there was an error getting module ID %s from the repository", err))
		return
	}

	// Build the response message to display
	var msg string
	msg += fmt.Sprintf("\n'%s' module information\n", m.Name())
	msg += fmt.Sprintf("\nPlatform:\n\t%s\\%s\\%s\n", m.Platform(), m.Arch(), m.Lang())
	msg += "Module Authors:\n"
	for _, a := range m.Author() {
		msg += fmt.Sprintf("\t%s\n", a)
	}
	msg += "Credits:\n"
	for _, credit := range m.Credits() {
		msg += fmt.Sprintf("\t%s\n", credit)
	}
	msg += fmt.Sprintf("Description:\n\t%s\n", m.Description())

	// Build the options' table
	msg += "Options:\n\n"
	builder := &strings.Builder{}
	table := tablewriter.NewWriter(builder)
	table.SetHeader([]string{"Name", "Value", "Required", "Description"})
	table.SetBorder(false)
	table.Append([]string{"Agent", m.Agent(), "true", "Agent on which to run module " + m.Name()})
	for _, v := range m.Options() {
		table.Append([]string{v.Name, v.Value, strconv.FormatBool(v.Required), v.Description})
	}
	table.Render()
	msg += builder.String()
	msg += fmt.Sprintf("Notes:\n\t%s", m.Notes())

	response.Message = message.NewUserMessage(message.Info, msg)
	return
}

// Help returns a help.Help structure that can be used to view a command's Description, Notes, Usage, and an example
func (c *Command) Help(m menu.Menu) help.Help {
	h, ok := c.help[m]
	if !ok {
		return help.NewHelp(fmt.Sprintf("the 'info' command's Help structure does not exist for the %s menu", m), "", "", "")
	}
	return h
}

// Menu checks to see if the command is supported for the provided menu
func (c *Command) Menu(m menu.Menu) bool {
	for _, v := range c.menus {
		if v == m || v == menu.ALLMENUS {
			return true
		}
	}
	return false
}

// OS returns the supported operating system the Agent command can be executed on
func (c *Command) OS() os.OS {
	return c.os
}

// String returns the unique name of the command as a string
func (c *Command) String() string {
	return c.name
}
