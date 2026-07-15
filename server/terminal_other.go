//go:build !windows

package main

// isTerminal 非Windows平台默认启用控制台
func isTerminal() bool {
	return true
}
