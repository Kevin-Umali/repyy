//go:build !unix

package scan

import "os"

func openConfinedNonblocking(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
