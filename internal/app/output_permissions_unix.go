//go:build !windows

package app

func restrictOutputPermissions(string) error { return nil }
