package createprocess

import (
	// Standard
	"encoding/base64"
	"fmt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/modules/shellcode"
)

// Parse is the initial entry point for all extended modules. All validation checks and processing will be performed here
// The function input types are limited to strings and therefore require additional processing
func Parse(options map[string]string) ([]string, error) {
	// 1. Shellcode
	// 2. SpawnTo
	// 3. Arguments
	if len(options) != 3 {
		return nil, fmt.Errorf("3 arguments were expected, %d were provided", len(options))
	}
	sc, err := shellcode.ParseShellcode(options["shellcode"])
	if err != nil {
		return nil, err
	}
	return []string{"CreateProcess", base64.StdEncoding.EncodeToString(sc), options["spawnto"], options["args"]}, nil
}
