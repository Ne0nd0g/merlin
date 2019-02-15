package util

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/Ne0nd0g/merlin/pkg/messages"
)

//ValidCompilerTargets is all the valid compiler targets? greetz 2 moloch--
var ValidCompilerTargets = map[string]bool{
	"darwin/386":      true,
	"darwin/amd64":    true,
	"dragonfly/amd64": true,
	"freebsd/386":     true,
	"freebsd/amd64":   true,
	"freebsd/arm":     true,
	"linux/386":       true,
	"linux/amd64":     true,
	"linux/arm":       true,
	"linux/arm64":     true,
	"linux/ppc64":     true,
	"linux/ppc64le":   true,
	"linux/mips":      true,
	"linux/mipsle":    true,
	"linux/mips64":    true,
	"linux/mips64le":  true,
	"linux/s390x":     true,
	"netbsd/386":      true,
	"netbsd/amd64":    true,
	"netbsd/arm":      true,
	"openbsd/386":     true,
	"openbsd/amd64":   true,
	"openbsd/arm":     true,
	"plan9/386":       true,
	"plan9/amd64":     true,
	"plan9/arm":       true,
	"solaris/amd64":   true,
	"windows/386":     true,
	"windows/amd64":   true,
}

//ValidGoos returns a list of valid Goos compiler targets
func ValidGoos(string) []string {
	return []string{
		"darwin",
		"dragonfly",
		"freebsd",
		"linux",
		"netbsd",
		"openbsd",
		"plan9",
		"solaris",
		"windows",
	}
}

//ValidGoarch returns a list of valid goarch compiler targets
func ValidGoarch(string) []string {
	return []string{
		"386",
		"amd64",
		"arm",
		"arm64",
		"ppc64",
		"ppc64le",
		"mips",
		"mipsle",
		"mips64",
		"mips64le",
		"s390x",
	}
}

//GoConfig is a configuration of values useful to the go compiler
type GoConfig struct {
	CGO    string
	GOOS   string
	GOARCH string
	GOROOT string
	GOPATH string
}

//GoCmd runs a command with the provided env config, in the specified directory
func GoCmd(config GoConfig, cwd string, command []string) error {
	target := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)
	if _, ok := ValidCompilerTargets[target]; !ok {
		return fmt.Errorf(fmt.Sprintf("Invalid compiler target: %s", target))
	}
	ldf := "-w -s"
	if config.GOOS == "windows" {
		ldf += " -H windowsgui"
	}
	command = append(command, "-ldflags")
	command = append(command, ldf)

	command = append(command, "") //strip binary
	cmd := exec.Command("go", command...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, []string{
		fmt.Sprintf("CGO_ENABLED=%s", config.CGO),
		fmt.Sprintf("GOOS=%s", config.GOOS),
		fmt.Sprintf("GOARCH=%s", config.GOARCH),
		fmt.Sprintf("GOROOT=%s", config.GOROOT),
		fmt.Sprintf("GOPATH=%s", config.GOPATH),
		fmt.Sprintf("PATH=%sbin", config.GOROOT),
	}...)
	messages.Message("info", "Executing the following command:")
	messages.Message("info", fmt.Sprintf("go %v", command))
	messages.Message("info", "with env:")
	messages.Message("info", fmt.Sprintf("%+v", config))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil { //if err,
		messages.Message("info", fmt.Sprintf("--- stdout ---\n%s\n", stdout.String()))
		messages.Message("info", fmt.Sprintf("--- stderr ---\n%s\n", stderr.String()))
		messages.Message("error", err.Error())
	} else {
		messages.Message("info", fmt.Sprintf("Agent successfully generated at: %s", cwd))
	}
	return err
}
