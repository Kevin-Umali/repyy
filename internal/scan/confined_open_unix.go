//go:build unix

package scan

import (
	"os"
	"syscall"
)

func openConfinedNonblocking(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
