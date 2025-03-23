package command

import (
	"bytes"
	"fmt"
	"os/exec"
)

// Run executes a command and returns combined output or an error.
func Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Uncomment the next line to log the commands being executed.
	// log.Printf("Executing command: %s %s", name, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %s %v failed: %w - %s", name, args, err, stderr.String())
	}
	return nil
}
