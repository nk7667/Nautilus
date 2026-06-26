//go:build linux

package core

import (
	"net"
	"strings"
)

func getIPs() []string {
	// 优先用Go标准库获取接口IP
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return getIPsCmd()
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			ips = append(ips, ipNet.IP.String())
		}
	}
	if len(ips) > 0 {
		return ips
	}
	// fallback到ip命令
	return getIPsCmd()
}

func getIPsCmd() []string {
	out, err := ExecCmdWithShell("ip addr show")
	if err != nil {
		return nil
	}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := strings.Split(parts[1], "/")[0]
				ips = append(ips, ip)
			}
		}
	}
	return ips
}
