//go:build linux

package main

import "fmt"

// handlePayload Linux不支持远程载荷执行
func handlePayload(params map[string]string) string {
	return fmt.Sprintf("payload exec not supported on Linux")
}
