package Exfiltration

import (
	"github.com/ne0nd0g/merlin/pkg/modules"
)

var module = modules.Module{
	Name: "Invoke-Mimikatz",
	Author: append("Joe Bialek", "Benjamin DELPY `gentilkiwi`"),
	Path: "PowerSploit/Exfiltration/Invoke-Mimikatz.ps1",
	Platform: "windows",
	Arch: "amd64",
	Lang: "powershell",
	Notes: "",
}

type Options struct {
	Module modules.Module
	Command	[]string
	Arguments string

}

func (o Options) check() bool{

	return true
}

func main() *Options {
	o := Options{
		Command: append("DumpCreds", "DumpCerts", "Command", "ComputerName"),
		Module: module,
		Arguments: "",
	}
	return o
}