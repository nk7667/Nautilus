// PE Section Name Obfuscator
// 修改Go二进制的PE Section名，破坏Go二进制结构指纹
// Go默认section: .text, .rdata, .data, .pdata, .rsrc, .reloc
// 替换为无害名称，破坏ClamAV的Go/Sliver结构签名
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: pesectionobf <pefile>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	// 验证PE签名
	if len(data) < 64 || string(data[0:2]) != "MZ" {
		fmt.Println("Not a valid PE file")
		os.Exit(1)
	}

	// 获取PE头偏移
	peOffset := int(binary.LittleEndian.Uint32(data[60:64]))
	if peOffset+4 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		fmt.Println("Invalid PE header")
		os.Exit(1)
	}

	// COFF Header
	coffOffset := peOffset + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2 : coffOffset+4]))
	optionalHeaderSize := int(binary.LittleEndian.Uint16(data[coffOffset+16 : coffOffset+18]))

	// Section Header起始位置
	sectionStart := coffOffset + 20 + optionalHeaderSize

	// Section名替换映射 (8字节，\0结尾)
	// 使用无害的名称，看起来像正常应用
	replacements := map[string][8]byte{
		".text\x00\x00\x00": {'.', 'c', 'o', 'd', 'e', '\x00', '\x00', '\x00'},
		".rdata\x00\x00":    {'.', 'r', 'o', '\x00', '\x00', '\x00', '\x00', '\x00'},
		".data\x00\x00\x00": {'.', 'd', 'a', 't', '\x00', '\x00', '\x00', '\x00'},
		".pdata\x00\x00":    {'.', 'p', 'd', 'a', '\x00', '\x00', '\x00', '\x00'},
		".rsrc\x00\x00\x00": {'.', 'r', 's', 'r', 'c', '\x00', '\x00', '\x00'},
		".reloc\x00\x00":    {'.', 'r', 'e', 'l', 'o', '\x00', '\x00', '\x00'},
		".symtab\x00":       {'.', 's', 'y', 'm', '\x00', '\x00', '\x00', '\x00'},
		".gosymtab\x00":     {'.', 'g', 's', 'y', 'm', '\x00', '\x00', '\x00'},
		".gopclntab\x00":    {'.', 'g', 'p', 'c', 'l', 'n', '\x00', '\x00'},
		".go.buildinfo":     {'.', 'g', 'b', 'i', 'n', 'f', 'o', '\x00'},
	}

	modified := 0
	for i := 0; i < numSections; i++ {
		secOffset := sectionStart + i*40
		if secOffset+40 > len(data) {
			break
		}

		secName := string(data[secOffset : secOffset+8])
		fmt.Printf("  Section %d: %q\n", i, secName)

		for orig, repl := range replacements {
			if secName == orig {
				copy(data[secOffset:secOffset+8], repl[:])
				fmt.Printf("    -> renamed to %q\n", string(repl[:]))
				modified++
				break
			}
		}
	}

	if modified > 0 {
		err = os.WriteFile(os.Args[1], data, 0644)
		if err != nil {
			fmt.Printf("Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n[+] %d section names obfuscated\n", modified)
	} else {
		fmt.Println("\n[+] No standard Go section names found to obfuscate")
	}
}
