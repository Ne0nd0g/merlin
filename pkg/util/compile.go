package util

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
)

//greetz 2 moloch--
var validCompilerTargets = map[string]bool{
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

type GoConfig struct {
	CGO     string
	GOOS    string
	GOARCH  string
	GOROOT  string
	GOPATH  string
	LDFLAGS []string
}

func GoCmd(config GoConfig, cwd string, command []string) error {
	target := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)
	if _, ok := validCompilerTargets[target]; !ok {
		return fmt.Errorf(fmt.Sprintf("Invalid compiler target: %s", target))
	}
	ldf := "-w -s"
	if config.GOOS == "windows" {
		ldf += " -H windowsgui"
	}
	command = append(command, "-ldflags")
	command = append(command, ldf)

	command = append(command) //strip binary
	fmt.Println("Executing: go", command)
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

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("--- stdout ---\n%s\n", stdout.String())
		log.Printf("--- stderr ---\n%s\n", stderr.String())
		log.Print(err)
	}

	return err
}
