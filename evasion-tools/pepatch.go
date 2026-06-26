package main

import (
	"fmt"
	"os"
	"time"

	"nautilus/evasion"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: pepatch <pefile>")
		os.Exit(1)
	}

	path := os.Args[1]

	// 读取当前时间戳
	oldTS, err := evasion.ReadPETimestamp(path)
	if err != nil {
		fmt.Printf("Error reading timestamp: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Original timestamp: %d\n", oldTS)

	// 修改为随机时间戳
	newTS := uint32(time.Now().Unix())
	err = evasion.ModifyPETimestamp(path, newTS)
	if err != nil {
		fmt.Printf("Error modifying timestamp: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("New timestamp: %d\n", newTS)

	fmt.Println("[+] PE timestamp patched")
}
