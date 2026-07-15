//go:build windows

package core

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"syscall"
	"unsafe"
)

var (
	gdi32  = syscall.NewLazyDLL("gdi32.dll")
	user32 = syscall.NewLazyDLL("user32.dll")

	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
)

const (
	SM_CXSCREEN    = 0
	SM_CYSCREEN    = 1
	SRCCOPY        = 0x00CC0020
	DIB_RGB_COLORS = 0
	BI_RGB         = 0
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	_      [4]uint32 // dummy color table
}

// CaptureScreenshot 截取整个桌面屏幕，返回PNG格式的字节切片
func CaptureScreenshot() ([]byte, error) {
	// 获取屏幕尺寸
	w, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	h, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	width := int(w)
	height := int(h)
	if width == 0 || height == 0 {
		return nil, fmt.Errorf("failed to get screen size")
	}

	// 获取桌面DC
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdcScreen)

	// 创建兼容DC
	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hdcMem)

	// 创建兼容位图
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, uintptr(width), uintptr(height))
	if hBitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hBitmap)

	// 选择位图到DC
	oldBitmap, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	defer procSelectObject.Call(hdcMem, oldBitmap)

	// 复制屏幕到位图
	ret, _, _ := procBitBlt.Call(hdcMem, 0, 0, uintptr(width), uintptr(height), hdcScreen, 0, 0, SRCCOPY)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}

	// 读取像素数据
	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:       int32(width),
			Height:      -int32(height), // 负值表示从上到下
			Planes:      1,
			BitCount:    32,
			Compression: BI_RGB,
		},
	}
	bi.Header.SizeImage = uint32(width * height * 4)

	pixels := make([]byte, bi.Header.SizeImage)
	ret, _, _ = procGetDIBits.Call(
		hdcMem, hBitmap,
		0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bi)), DIB_RGB_COLORS,
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}

	// 构建image.RGBA
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	copy(img.Pix, pixels)

	// 编码为PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode failed: %v", err)
	}
	return buf.Bytes(), nil
}
