// +build windows

package agent

import (
	"os/exec"
	"strings"
	"syscall"
)

func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	cmd = exec.Command(name, strings.Fields(arg)...)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} //Only difference between this and agent.go

	out, err := cmd.CombinedOutput();
	stdout = string(out);
	stderr = "";

	if err != nil {
		stderr = err.Error();
	}

	return stdout, stderr
}