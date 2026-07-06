//go:build ignore
// +build ignore

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: postprocess <file>")
		os.Exit(1)
	}

	filename := os.Args[1]
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("[!] Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] File loaded: %s (%d bytes)\n", filename, len(data))

	// 重命名PE section
	renamePESections(data)

	// 降低.text段熵值
	reduceTextEntropy(data)

	// 敏感字符串列表
	patterns := []string{
		"Go build ID: ",
		"Go buildinf",
		"go.buildid",
		"runtime.main",
		"runtime.goexit",
		"main.main",
		"runtime.init",
		"runtime.gc",
		"runtime.morestack",
		"runtime.gcWriteBarrier",
		"runtime.writebarrier",
		"runtime.allocmon",
		"type..eq",
		"type..hash",
		"shellcode",
		"VirtualAlloc",
		"VirtualProtect",
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"AmsiScanBuffer",
		"EtwEventWrite",
		"CreateRemoteThread",
		"WriteProcessMemory",
		"ntdll",
		"kernel32",
		"EnumWindows",
		"NtWriteVirtualMemory",
		"NtCreateThread",
		"RtlCopyMemory",
		"GetProcAddress",
		"LoadLibrary",
		"user32",
		"EnumChildWindows",
		"GetDesktopWindow",
		"GetWindowText",
		"GetTickCount",
		"GetTickCount64",
		"IsDebuggerPresent",
		"GlobalMemoryStatus",
		"GlobalMemoryStatusEx",
		"CreateFile",
		"ReadFile",
		"CloseHandle",
		"GetFileSize",
		"nautilus",
		"fish",
		"C2",
		"implant",
		"stager",
		"golang.org/x/crypto",
		"crypto/aes",
		"crypto/rand",
		"crypto/sha",
		"encoding/base64",
		"net/http",
		"net.Dial",
		"reflect.TypeOf",
		"fmt.Sprintf",
	}

	// 字符串清零
	fmt.Println("[+] Zeroing sensitive strings...")
	replaced := 0
	for _, pattern := range patterns {
		patternBytes := []byte(pattern)
		for i := 0; i <= len(data)-len(patternBytes); i++ {
			found := true
			for j := 0; j < len(patternBytes); j++ {
				if data[i+j] != patternBytes[j] {
					found = false
					break
				}
			}
			if found {
				for j := 0; j < len(patternBytes); j++ {
					data[i+j] = 0x00
				}
				replaced++
			}
		}
	}
	fmt.Printf("[+] Strings zeroed: %d occurrences\n", replaced)

	// 清除Rich Header
	fmt.Println("[+] Clearing Rich Header...")
	richSig := []byte("Rich")
	for i := 0; i < len(data) && i < 4096; i++ {
		found := true
		for j := 0; j < 4; j++ {
			if data[i+j] != richSig[j] {
				found = false
				break
			}
		}
		if found {
			richEnd := i + 8
			richStart := i
			for k := i - 1; k >= 0; k-- {
				if data[k] == 0x53 && data[k+1] == 0x6E && data[k+2] == 0x61 && data[k+3] == 0x44 {
					richStart = k
					break
				}
			}
			for k := richStart; k < richEnd && k < len(data); k++ {
				data[k] = 0x00
			}
			fmt.Printf("[+] Rich Header cleared at offset %d\n", richStart)
			break
		}
	}

	// 添加overlay (32KB随机数据+ZIP签名)
	fmt.Println("[+] Appending 32KB overlay...")
	overlaySize := 32 * 1024
	randomBytes := make([]byte, overlaySize)
	rand.Read(randomBytes)
	// 添加假的ZIP签名
	randomBytes[0] = 0x50
	randomBytes[1] = 0x4B
	randomBytes[2] = 0x03
	randomBytes[3] = 0x04

	data = append(data, randomBytes...)
	fmt.Printf("[+] Overlay appended: %d bytes\n", overlaySize)

	// 写入文件
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("[!] Error writing file: %v\n", err)
		os.Exit(1)
	}

	// 显示文件哈希
	hash := hex.EncodeToString(data[:min(32, len(data))])
	fmt.Printf("[+] File saved: %s\n", filename)
	fmt.Printf("[+] File size: %d bytes\n", len(data))
	fmt.Printf("[+] First bytes: %s...\n", hash[:32])

	// 读取并显示新的文件大小
	info, _ := os.Stat(filename)
	fmt.Printf("[+] Final size: %d bytes (%.2f MB)\n", info.Size(), float64(info.Size())/1024/1024)
}

func renamePESections(data []byte) {
	fmt.Println("[+] Renaming PE sections...")

	if len(data) < 64 {
		fmt.Println("[-] File too small")
		return
	}

	dosHeader := data[:64]
	if dosHeader[0] != 0x4D || dosHeader[1] != 0x5A {
		fmt.Println("[-] Not a PE file")
		return
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[0x3C:0x40])
	if int(peOffset)+4 > len(data) {
		fmt.Println("[-] Invalid PE offset")
		return
	}

	peHeader := data[peOffset:]
	if string(peHeader[:4]) != "PE\x00\x00" {
		fmt.Println("[-] Invalid PE signature")
		return
	}

	if int(peOffset)+24 > len(data) {
		fmt.Println("[-] PE header too small")
		return
	}

	numSections := binary.LittleEndian.Uint16(peHeader[6:8])
	optionalHeaderOffset := 24
	optionalHeaderSize := binary.LittleEndian.Uint16(peHeader[20:22])
	sectionTableOffset := peOffset + uint32(optionalHeaderOffset) + uint32(optionalHeaderSize)

	sectionRenameMap := map[string]string{
		".text":         ".text",
		".data":         ".data",
		".rdata":        ".rdata",
		".bss":          ".bss",
		".rsrc":         ".rsrc",
		".reloc":        ".reloc",
		".go.buildinfo": ".rdata",
		".gopclntab":    ".data",
		".noptrdata":    ".rdata",
		".ptrdata":      ".data",
		".textflag":     ".text",
		".itablink":     ".rdata",
		".gofunctab":    ".data",
		".rodata":       ".rdata",
		".typelink":     ".rdata",
	}

	for i := uint16(0); i < numSections; i++ {
		sectionOffset := sectionTableOffset + uint32(i)*40
		if int(sectionOffset)+8 > len(data) {
			break
		}

		sectionName := string(data[sectionOffset : sectionOffset+8])
		sectionName = sectionName[:len(sectionName)-len([]byte(sectionName))+len([]byte(sectionName))]
		for j := 0; j < 8 && j < len(sectionName); j++ {
			if sectionName[j] == 0 {
				sectionName = sectionName[:j]
				break
			}
		}

		newName, ok := sectionRenameMap[sectionName]
		if !ok {
			newName = ".data"
		}

		if sectionName != newName {
			copy(data[sectionOffset:sectionOffset+8], []byte(newName))
			for j := len(newName); j < 8; j++ {
				data[sectionOffset+uint32(j)] = 0
			}
			fmt.Printf("[+] Renamed section: %s -> %s\n", sectionName, newName)
		}
	}
}

func reduceTextEntropy(data []byte) {
	fmt.Println("[+] Reducing .text section entropy...")

	if len(data) < 64 {
		fmt.Println("[-] File too small")
		return
	}

	dosHeader := data[:64]
	if dosHeader[0] != 0x4D || dosHeader[1] != 0x5A {
		fmt.Println("[-] Not a PE file")
		return
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[0x3C:0x40])
	if int(peOffset)+4 > len(data) {
		fmt.Println("[-] Invalid PE offset")
		return
	}

	peHeader := data[peOffset:]
	if string(peHeader[:4]) != "PE\x00\x00" {
		fmt.Println("[-] Invalid PE signature")
		return
	}

	if int(peOffset)+24 > len(data) {
		fmt.Println("[-] PE header too small")
		return
	}

	numSections := binary.LittleEndian.Uint16(peHeader[6:8])
	optionalHeaderOffset := 24
	optionalHeaderSize := binary.LittleEndian.Uint16(peHeader[20:22])
	sectionTableOffset := peOffset + uint32(optionalHeaderOffset) + uint32(optionalHeaderSize)

	for i := uint16(0); i < numSections; i++ {
		sectionOffset := sectionTableOffset + uint32(i)*40
		if int(sectionOffset)+40 > len(data) {
			break
		}

		sectionName := string(data[sectionOffset : sectionOffset+8])
		for j := 0; j < 8 && j < len(sectionName); j++ {
			if sectionName[j] == 0 {
				sectionName = sectionName[:j]
				break
			}
		}

		if sectionName == ".text" {
			rawOffset := binary.LittleEndian.Uint32(data[sectionOffset+20 : sectionOffset+24])
			rawSize := binary.LittleEndian.Uint32(data[sectionOffset+16 : sectionOffset+20])

			if int(rawOffset)+int(rawSize) > len(data) {
				fmt.Println("[-] .text section out of bounds")
				break
			}

			textData := data[rawOffset : rawOffset+rawSize]
			currentEntropy := shannonEntropy(textData)
			fmt.Printf("[+] Current .text entropy: %.3f\n", currentEntropy)

			targetEntropy := 6.0
			if currentEntropy > targetEntropy {
				paddingSize := int(float64(len(textData)) * (currentEntropy - targetEntropy) / (8.0 - targetEntropy))
				paddingSize = (paddingSize + 4095) & ^4095

				if paddingSize > 0 {
					padding := make([]byte, paddingSize)
					for j := 0; j < paddingSize; j += 8 {
						copy(padding[j:min(j+8, paddingSize)], []byte{0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x90, 0x90})
					}

					data = append(data[:rawOffset+rawSize], padding...)
					data = append(data, data[rawOffset+rawSize:]...)

					binary.LittleEndian.PutUint32(data[sectionOffset+16:sectionOffset+20], rawSize+uint32(paddingSize))

					newEntropy := shannonEntropy(data[rawOffset : rawOffset+rawSize+uint32(paddingSize)])
					fmt.Printf("[+] Added %d bytes padding, new entropy: %.3f\n", paddingSize, newEntropy)
				}
			}
			break
		}
	}
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	total := float64(len(data))
	for _, count := range freq {
		prob := float64(count) / total
		entropy -= prob * math.Log2(prob)
	}

	return entropy
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
