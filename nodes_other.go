//go:build !unix

package koloswarm

import "os"

func openNodeFile(path string) (*os.File, error) { return os.Open(path) }
