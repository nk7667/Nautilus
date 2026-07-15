//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal 检测stdin是否为交互式控制台
func isTerminal() bool {
	var mode uint32
	fd := os.Stdin.Fd()
	err := windows.GetConsoleMode(windows.Handle(fd), &mode)
	return err == nil
}
