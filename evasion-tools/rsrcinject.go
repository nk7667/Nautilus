//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

type VersionInfo struct {
	CompanyName      string
	ProductName      string
	FileDescription  string
	FileVersion      string
	ProductVersion   string
	InternalName     string
	OriginalFilename string
	Copyright        string
}

func buildVersionInfo(vi VersionInfo) []byte {
	var buf bytes.Buffer

	vsVersionInfo := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x56, 0x53, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4F,
		0x4E, 0x49, 0x4E, 0x46, 0x4F, 0x00, 0x00, 0x00,
	}
	buf.Write(vsVersionInfo)

	fixedInfo := []byte{
		0x18, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	buf.Write(fixedInfo)

	transTable := []byte{
		0x09, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x4D, 0x43, 0x48, 0x49, 0x4E, 0x47, 0x00, 0x00,
	}
	buf.Write(transTable)

	writeStringFileInfo(&buf, "CompanyName", vi.CompanyName)
	writeStringFileInfo(&buf, "FileDescription", vi.FileDescription)
	writeStringFileInfo(&buf, "FileVersion", vi.FileVersion)
	writeStringFileInfo(&buf, "InternalName", vi.InternalName)
	writeStringFileInfo(&buf, "OriginalFilename", vi.OriginalFilename)
	writeStringFileInfo(&buf, "ProductName", vi.ProductName)
	writeStringFileInfo(&buf, "ProductVersion", vi.ProductVersion)
	writeStringFileInfo(&buf, "LegalCopyright", vi.Copyright)

	result := buf.Bytes()
	size := len(result) + 8
	paddedSize := ((size + 3) / 4) * 4
	padded := make([]byte, paddedSize)
	copy(padded, result)

	var finalBuf bytes.Buffer
	binary.Write(&finalBuf, binary.LittleEndian, uint32(paddedSize))
	binary.Write(&finalBuf, binary.LittleEndian, uint32(1))
	finalBuf.Write(padded)

	return finalBuf.Bytes()
}

func writeStringFileInfo(buf *bytes.Buffer, name, value string) {
	nameBytes := []byte(name)
	valueBytes := []byte(value)

	length := 16 + len(nameBytes) + 2 + len(valueBytes) + 2
	paddedLength := ((length + 3) / 4) * 4

	binary.Write(buf, binary.LittleEndian, uint32(paddedLength))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.Write([]byte("STRING"))
	buf.Write([]byte{0x00, 0x00, 0x00})
	buf.Write([]byte("040904B0"))
	buf.Write([]byte{0x00, 0x00, 0x00})

	nameLen := len(nameBytes) + 1
	valueLen := len(valueBytes) + 1

	var childBuf bytes.Buffer
	binary.Write(&childBuf, binary.LittleEndian, uint32(nameLen+valueLen+8))
	binary.Write(&childBuf, binary.LittleEndian, uint32(0))
	buf.Write(childBuf.Bytes())

	buf.Write(nameBytes)
	buf.Write([]byte{0x00})
	if len(nameBytes)%2 != 0 {
		buf.Write([]byte{0x00})
	}

	buf.Write(valueBytes)
	buf.Write([]byte{0x00})
	if len(valueBytes)%2 != 0 {
		buf.Write([]byte{0x00})
	}

	padding := paddedLength - length
	for i := 0; i < padding; i++ {
		buf.Write([]byte{0x00})
	}
}

func buildManifest() []byte {
	manifest := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
    <assemblyIdentity version="1.0.0.0" name="apphelper" type="win32"/>
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
            </requestedPrivileges>
        </security>
    </trustInfo>
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
        <application>
            <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
            <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
            <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
            <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
            <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
        </application>
    </compatibility>
</assembly>`
	return []byte(manifest)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: rsrcinject <file>")
		os.Exit(1)
	}

	filename := os.Args[1]
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("[!] Error reading file: %v\n", err)
		os.Exit(1)
	}

	if len(data) < 64 {
		fmt.Println("[!] File too small")
		os.Exit(1)
	}

	peOffset := int(binary.LittleEndian.Uint32(data[60:64]))
	if peOffset+4 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		fmt.Println("[!] Not a PE file")
		os.Exit(1)
	}

	fmt.Printf("[+] PE file detected, offset: 0x%X\n", peOffset)

	numSections := int(binary.LittleEndian.Uint16(data[peOffset+6 : peOffset+8]))
	fmt.Printf("[+] Number of sections: %d\n", numSections)

	sectionTableOffset := peOffset + 24 + 112
	fmt.Printf("[+] Section table offset: 0x%X\n", sectionTableOffset)

	sectionAlignment := uint32(0x1000)
	fileAlignment := uint32(0x200)

	var lastRawEnd uint32 = 0
	var lastVAEnd uint32 = 0

	for i := 0; i < numSections; i++ {
		offset := sectionTableOffset + i*40
		if offset+40 > len(data) {
			break
		}
		name := string(data[offset : offset+8])
		virtualSize := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		virtualAddress := binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		rawSize := binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		rawOffset := binary.LittleEndian.Uint32(data[offset+20 : offset+24])

		endRaw := rawOffset + rawSize
		if endRaw > lastRawEnd {
			lastRawEnd = endRaw
		}

		endVA := virtualAddress + virtualSize
		if endVA > lastVAEnd {
			lastVAEnd = endVA
		}

		fmt.Printf("[+] Section %d: %s (VA:0x%X, Raw:0x%X, Size:%d)\n", i+1, name, virtualAddress, rawOffset, rawSize)
	}

	fmt.Printf("[+] Last raw end: 0x%X\n", lastRawEnd)
	fmt.Printf("[+] Last VA end: 0x%X\n", lastVAEnd)

	versionInfo := buildVersionInfo(VersionInfo{
		CompanyName:      "Microsoft Corporation",
		ProductName:      "Windows App Helper",
		FileDescription:  "System Utility Application",
		FileVersion:      "1.0.0.1",
		ProductVersion:   "1.0.0.1",
		InternalName:     "apphelper",
		OriginalFilename: "apphelper.exe",
		Copyright:        "Copyright (C) Microsoft Corporation. All rights reserved.",
	})

	manifest := buildManifest()

	rsrcData := bytes.Buffer{}
	rsrcData.Write(versionInfo)
	rsrcData.Write(manifest)

	rsrcSize := rsrcData.Len()
	paddedSize := ((rsrcSize + 3) / 4) * 4
	padded := make([]byte, paddedSize)
	copy(padded, rsrcData.Bytes())

	rawOffset := ((lastRawEnd + fileAlignment - 1) / fileAlignment) * fileAlignment
	virtualSize := uint32(paddedSize)
	virtualAddress := ((lastVAEnd + sectionAlignment - 1) / sectionAlignment) * sectionAlignment

	fmt.Printf("[+] New .rsrc section:\n")
	fmt.Printf("    - Name: .rsrc\n")
	fmt.Printf("    - Virtual Address: 0x%X\n", virtualAddress)
	fmt.Printf("    - Virtual Size: 0x%X\n", virtualSize)
	fmt.Printf("    - Raw Offset: 0x%X\n", rawOffset)
	fmt.Printf("    - Raw Size: 0x%X\n", paddedSize)

	newData := make([]byte, rawOffset+uint32(paddedSize))
	copy(newData, data)

	copy(newData[rawOffset:rawOffset+uint32(paddedSize)], padded)

	newSectionEntry := make([]byte, 40)
	copy(newSectionEntry, []byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	binary.LittleEndian.PutUint32(newSectionEntry[8:12], virtualSize)
	binary.LittleEndian.PutUint32(newSectionEntry[12:16], virtualAddress)
	binary.LittleEndian.PutUint32(newSectionEntry[16:20], uint32(paddedSize))
	binary.LittleEndian.PutUint32(newSectionEntry[20:24], rawOffset)

	sectionTableStart := sectionTableOffset + numSections*40
	copy(newData[sectionTableStart:sectionTableStart+40], newSectionEntry)

	binary.LittleEndian.PutUint16(newData[peOffset+6:peOffset+8], uint16(numSections+1))

	err = ioutil.WriteFile(filename, newData, 0644)
	if err != nil {
		fmt.Printf("[!] Error writing file: %v\n", err)
		os.Exit(1)
	}

	info, _ := os.Stat(filename)
	fmt.Printf("[+] Success! File saved: %s\n", filename)
	fmt.Printf("[+] New size: %d bytes (%.2f MB)\n", info.Size(), float64(info.Size())/1024/1024)
	fmt.Printf("[+] .rsrc section added with version info and manifest\n")
}
