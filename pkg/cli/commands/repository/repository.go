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

// Package repository implements an in-memory database that holds a map of Command structures used with the Merlin CLI
package repository

import (
	// Standard
	"errors"
	"fmt"
	"sync"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/commands"
	"github.com/Ne0nd0g/merlin/pkg/cli/entity/menu"

	// Agent - All
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/cd"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/checkin"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/connect"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/download"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/env"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/exit"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/ifconfig"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/ipconfig"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/ja3"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/kill"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/killdate"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/link"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/listener"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/ls"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/maxretry"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/note"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/nslookup"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/padding"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/printenv"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/pwd"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/rm"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/sdelete"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/shell"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/skew"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/sleep"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/ssh"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/touch"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/unlink"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/all/upload"

	// Agent - Linux
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/linux/memfd"

	// Agent - Windows
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/execute_assembly"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/execute_pe"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/execute_shellcode"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/invoke_assembly"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/list_assemblies"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/load_assembly"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/load_clr"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/make_token"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/memory"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/netstat"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/pipes"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/ps"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/rev2self"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/runas"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/sharpgen"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/steal_token"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/token"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/agent/windows/uptime"

	// All Menus
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/back"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/banner"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/clear"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/debug"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/exclamation"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/interact"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/listeners"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/mainmenu"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/modules"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/quit"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/sessions"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/all/verbose"

	// Listeners Menu
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/configure"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/delete"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/list"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/restart"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/start"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/stop"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/listeners/use"

	// Main Menu
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/mainMenu/group"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/mainMenu/queue"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/mainMenu/remove"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/mainMenu/version"

	// Module Menu
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/module/reload"

	// Multiple Menus
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/info"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/jobs"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/run"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/set"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/show"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/socks"
	"github.com/Ne0nd0g/merlin/pkg/cli/commands/multi/status"
)

var pkg = "pkg/cli/commands/memory.go"
var ErrCommandNotFound = errors.New(fmt.Sprintf("%s: command not found", pkg))
var ErrCommandNotInMenu = errors.New(fmt.Sprintf("%s: command not in menu", pkg))

// Repository structure implements an in-memory database that holds a map of Command structures used with the Merlin CLI
type Repository struct {
	// Don't use pointers because this map is the source and should only be modified here in the repository
	commands map[string]commands.Command
	sync.Mutex
}

// repo is the in-memory database
var repo *Repository

// NewRepository creates and returns a Repository structure that contains an in-memory map of agents
func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			commands: make(map[string]commands.Command),
		}
		repo.load()
	}
	return repo
}

func (r *Repository) Add(cmd commands.Command) {
	r.Lock()
	defer r.Unlock()
	r.commands[cmd.String()] = cmd
	return
}

func (r *Repository) Get(m menu.Menu, cmd string) (command commands.Command, err error) {
	r.Lock()
	defer r.Unlock()
	var ok bool
	if command, ok = r.commands[cmd]; ok {
		if command.Menu(m) {
			return
		}
		err = ErrCommandNotInMenu
		return
	}
	err = ErrCommandNotFound
	return
}

func (r *Repository) GetAll() (commands []commands.Command) {
	r.Lock()
	defer r.Unlock()
	for _, cmd := range r.commands {
		commands = append(commands, cmd)
	}
	return
}

func (r *Repository) load() {
	// Multiple menu commands
	// Typically the Agent menu and a Listener menu

	// All menus
	r.Add(back.NewCommand())
	r.Add(banner.NewCommand())
	r.Add(clear.NewCommand())
	r.Add(debug.NewCommand())
	r.Add(exclamation.NewCommand()) // This is for the `!` command
	r.Add(interact.NewCommand())
	r.Add(listeners.NewCommand())
	r.Add(mainmenu.NewCommand())
	r.Add(modules.NewCommand())
	r.Add(quit.NewCommand())
	r.Add(sessions.NewCommand())
	r.Add(verbose.NewCommand())

	// Listener menu
	r.Add(configure.NewCommand())
	r.Add(delete.NewCommand())
	r.Add(list.NewCommand())
	r.Add(restart.NewCommand())
	r.Add(start.NewCommand())
	r.Add(stop.NewCommand())
	r.Add(use.NewCommand())

	// Main menu
	r.Add(group.NewCommand())
	r.Add(queue.NewCommand())
	r.Add(remove.NewCommand())
	r.Add(version.NewCommand())

	// Module menu - the other commands are in the Multi menu
	r.Add(reload.NewCommand())

	// Multi menu
	r.Add(info.NewCommand())
	r.Add(jobs.NewCommand())
	r.Add(run.NewCommand())
	r.Add(set.NewCommand())
	r.Add(show.NewCommand())
	r.Add(socks.NewCommand())
	r.Add(status.NewCommand())

	// Agent - All commands
	r.Add(cd.NewCommand())
	r.Add(checkin.NewCommand())
	r.Add(connect.NewCommand())
	r.Add(download.NewCommand())
	r.Add(env.NewCommand())
	r.Add(exit.NewCommand())
	r.Add(ifconfig.NewCommand())
	r.Add(ipconfig.NewCommand())
	r.Add(ja3.NewCommand())
	r.Add(kill.NewCommand())
	r.Add(killdate.NewCommand())
	r.Add(link.NewCommand())
	r.Add(listener.NewCommand())
	r.Add(ls.NewCommand())
	r.Add(maxretry.NewCommand())
	r.Add(note.NewCommand())
	r.Add(nslookup.NewCommand())
	r.Add(padding.NewCommand())
	r.Add(printenv.NewCommand())
	r.Add(pwd.NewCommand())
	r.Add(rm.NewCommand())
	r.Add(sdelete.NewCommand())
	r.Add(shell.NewCommand())
	r.Add(skew.NewCommand())
	r.Add(sleep.NewCommand())
	r.Add(ssh.NewCommand())
	r.Add(touch.NewCommand())
	r.Add(unlink.NewCommand())
	r.Add(upload.NewCommand())

	// Agent - Linux commands
	r.Add(memfd.NewCommand())

	// Agent - Windows commands
	r.Add(execute_assembly.NewCommand())
	r.Add(execute_pe.NewCommand())
	r.Add(execute_shellcode.NewCommand())
	r.Add(invoke_assembly.NewCommand())
	r.Add(list_assemblies.NewCommand())
	r.Add(load_assembly.NewCommand())
	r.Add(load_clr.NewCommand())
	r.Add(make_token.NewCommand())
	r.Add(memory.NewCommand())
	r.Add(netstat.NewCommand())
	r.Add(pipes.NewCommand())
	r.Add(ps.NewCommand())
	r.Add(rev2self.NewCommand())
	r.Add(runas.NewCommand())
	r.Add(sharpgen.NewCommand())
	r.Add(steal_token.NewCommand())
	r.Add(token.NewCommand())
	r.Add(uptime.NewCommand())

}
