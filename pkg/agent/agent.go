// +build !windows

package agent

import (
	"os/exec"
	"strings"
)

func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	cmd = exec.Command(name, strings.Fields(arg)...)

	out, err := cmd.CombinedOutput();
	stdout = string(out);
	stderr = "";

	if err != nil {
		stderr = err.Error();
	}

	return stdout, stderr
}