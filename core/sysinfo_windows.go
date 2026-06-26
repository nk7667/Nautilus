//go:build windows

package core

import "strings"

func getIPs() []string {
	out, err := ExecCmdWithShell("ipconfig")
	if err != nil {
		return nil
	}
	var ips []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IPv4") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(parts[1])
				ips = append(ips, ip)
			}
		}
	}
	return ips
}
