//go:build windows

package app

import (
	"fmt"
	"os/exec"
	"os/user"
)

// A mode of 0600 does not restrict Windows ACLs. Remove inherited ACEs from
// the still-empty temporary report, then grant the current user access.
func restrictOutputPermissions(path string) error {
	current, err := user.Current()
	if err != nil {
		return err
	}
	identity := "*" + current.Uid + ":(F)"
	for _, args := range [][]string{{path, "/inheritance:r"}, {path, "/grant:r", identity}} {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("restrict report permissions: %w: %s", err, out)
		}
	}
	return nil
}
