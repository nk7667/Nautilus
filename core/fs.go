package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileRead 读取文件内容
func FileRead(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// FileWrite 写入文件内容
func FileWrite(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// FileDownload 从远程URL下载文件到本地 (由transport层调用)
func FileDownload(data []byte, dest string) error {
	return os.WriteFile(dest, data, 0644)
}

// FileUpload 读取本地文件准备上传
func FileUpload(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// FileRemove 删除文件
func FileRemove(path string) error {
	return os.Remove(path)
}

// FileCopy 复制文件
func FileCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// ListDir 列出目录内容
func ListDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, e := range entries {
		info, _ := e.Info()
		result = append(result, strings.Join([]string{
			e.Name(),
			fmt.Sprintf("%d", info.Size()),
			info.ModTime().Format("2006-01-02 15:04:05"),
			map[bool]string{true: "DIR", false: "FILE"}[e.IsDir()],
		}, " | "))
	}
	return result, nil
}

// MkDir 创建目录
func MkDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// GetCurrentDir 获取当前工作目录
func GetCurrentDir() string {
	dir, _ := os.Getwd()
	return dir
}

// WalkDir 递归遍历目录
func WalkDir(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		files = append(files, path)
		return nil
	})
	return files, err
}
