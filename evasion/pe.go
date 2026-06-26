//go:build windows

package evasion

import (
	"encoding/binary"
	"io"
	"os"
)

// PESection 定义PE节区结构
type PESection struct {
	Name            string
	VirtualSize     uint32
	VirtualAddr     uint32
	RawSize         uint32
	RawAddr         uint32
	Characteristics uint32
}

// ModifyPETimestamp 修改PE文件时间戳，降低静态特征匹配
func ModifyPETimestamp(path string, timestamp uint32) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// 读取DOS头，获取PE偏移
	var eLfanew uint32
	f.Seek(0x3C, io.SeekStart)
	if err := binary.Read(f, binary.LittleEndian, &eLfanew); err != nil {
		return err
	}

	// 写入新时间戳 (PE偏移+8处为TimeDateStamp)
	f.Seek(int64(eLfanew)+8, io.SeekStart)
	return binary.Write(f, binary.LittleEndian, timestamp)
}

// ModifyPESizeOfImage 修改PE的SizeOfImage，增加少量填充降低特征
func ModifyPESizeOfImage(path string, delta uint32) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	var eLfanew uint32
	f.Seek(0x3C, io.SeekStart)
	if err := binary.Read(f, binary.LittleEndian, &eLfanew); err != nil {
		return err
	}

	var sizeOfImage uint32
	f.Seek(int64(eLfanew)+0x50, io.SeekStart)
	if err := binary.Read(f, binary.LittleEndian, &sizeOfImage); err != nil {
		return err
	}

	sizeOfImage += delta
	f.Seek(int64(eLfanew)+0x50, io.SeekStart)
	return binary.Write(f, binary.LittleEndian, sizeOfImage)
}

// AppendOverlayData 在PE末尾附加overlay数据，改变文件哈希
func AppendOverlayData(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// ReadPETimestamp 读取PE时间戳
func ReadPETimestamp(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var eLfanew uint32
	f.Seek(0x3C, io.SeekStart)
	if err := binary.Read(f, binary.LittleEndian, &eLfanew); err != nil {
		return 0, err
	}

	var ts uint32
	f.Seek(int64(eLfanew)+8, io.SeekStart)
	if err := binary.Read(f, binary.LittleEndian, &ts); err != nil {
		return 0, err
	}
	return ts, nil
}
