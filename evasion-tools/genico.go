package main

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
)

// PDF icon - hand-drawn 32x32 pixel art of a PDF document icon
// White page with red "PDF" text, blue header bar
var pdfIcon32 = []byte{
	// 32x32 RGBA pixels - PDF document icon
	// Row 0: top border
	0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255,
	0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255,
	0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255,
	0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255,
	// Using a simpler approach - just create the icon programmatically
}

func createPDFIcon(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	// Background: light gray
	bgColor := color.NRGBA{220, 220, 220, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Document shape: white page with shadow
	margin := size / 8
	shadowOff := size / 16
	pageRect := image.Rect(margin+shadowOff, margin+shadowOff, size-margin, size-margin)
	shadowColor := color.NRGBA{180, 180, 180, 255}
	draw.Draw(img, pageRect, &image.Uniform{shadowColor}, image.Point{}, draw.Src)

	pageRect2 := image.Rect(margin, margin, size-margin-shadowOff, size-margin-shadowOff)
	pageColor := color.NRGBA{255, 255, 255, 255}
	draw.Draw(img, pageRect2, &image.Uniform{pageColor}, image.Point{}, draw.Src)

	// Red header bar on the page
	headerH := size / 6
	headerRect := image.Rect(margin, margin, size-margin-shadowOff, margin+headerH)
	redColor := color.NRGBA{200, 30, 30, 255}
	draw.Draw(img, headerRect, &image.Uniform{redColor}, image.Point{}, draw.Src)

	// "PDF" text approximation - white rectangles in header
	if size >= 16 {
		textY := margin + headerH/4
		textH := headerH / 2
		letterW := (size - 2*margin - shadowOff - size/8) / 3
		startX := margin + size/16

		// P
		draw.Draw(img, image.Rect(startX, textY, startX+letterW/3, textY+textH), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(startX, textY, startX+letterW, textY+textH/3), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(startX+letterW*2/3, textY+textH/3, startX+letterW, textY+textH), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)

		// D
		dStart := startX + letterW + letterW/4
		draw.Draw(img, image.Rect(dStart, textY, dStart+letterW/3, textY+textH), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(dStart, textY, dStart+letterW, textY+textH/4), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(dStart+letterW*2/3, textY+textH/4, dStart+letterW, textY+textH*3/4), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(dStart, textY+textH*3/4, dStart+letterW, textY+textH), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)

		// F
		fStart := dStart + letterW + letterW/4
		draw.Draw(img, image.Rect(fStart, textY, fStart+letterW/3, textY+textH), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(fStart, textY, fStart+letterW, textY+textH/3), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(fStart, textY+textH/2, fStart+letterW*2/3, textY+textH*2/3), &image.Uniform{color.NRGBA{255, 255, 255, 255}}, image.Point{}, draw.Src)
	}

	// Lines on page body (text lines)
	if size >= 16 {
		lineY := margin + headerH + size/10
		lineColor := color.NRGBA{160, 160, 160, 255}
		for i := 0; i < 3; i++ {
			y := lineY + i*(size/10)
			if y < size-margin-shadowOff-size/10 {
				draw.Draw(img, image.Rect(margin+size/8, y, size-margin-shadowOff-size/8, y+size/32), &image.Uniform{lineColor}, image.Point{}, draw.Src)
			}
		}
	}

	// Bottom right fold corner
	if size >= 16 {
		foldSize := size / 8
		foldX := size - margin - shadowOff - foldSize
		foldY := size - margin - shadowOff - foldSize
		foldColor := color.NRGBA{220, 220, 220, 255}
		draw.Draw(img, image.Rect(foldX, foldY, size-margin-shadowOff, size-margin-shadowOff), &image.Uniform{foldColor}, image.Point{}, draw.Src)
		draw.Draw(img, image.Rect(foldX, size-margin-shadowOff-foldSize/2, foldX+foldSize/2, size-margin-shadowOff), &image.Uniform{color.NRGBA{200, 200, 200, 255}}, image.Point{}, draw.Src)
	}

	return img
}

func writeICO(filename string, sizes []int) error {
	// Generate PNG data for each size
	pngDatas := make([][]byte, len(sizes))
	for i, sz := range sizes {
		img := createPDFIcon(sz)
		buf := new(bytesBuffer)
		if err := png.Encode(buf, img); err != nil {
			return fmt.Errorf("encoding %dx%d: %v", sz, sz, err)
		}
		pngDatas[i] = buf.Bytes()
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// ICO header
	binary.Write(f, binary.LittleEndian, uint16(0))          // Reserved
	binary.Write(f, binary.LittleEndian, uint16(1))          // Type = ICO
	binary.Write(f, binary.LittleEndian, uint16(len(sizes))) // Count

	// Directory entries
	dataOffset := uint32(6 + len(sizes)*16)
	for i, sz := range sizes {
		w := byte(sz)
		h := byte(sz)
		if sz >= 256 {
			w = 0
			h = 0
		}
		f.Write([]byte{w, h, 0, 0})                                    // Width, Height, Colors, Reserved
		binary.Write(f, binary.LittleEndian, uint16(1))                // Planes
		binary.Write(f, binary.LittleEndian, uint16(32))               // BPP
		binary.Write(f, binary.LittleEndian, uint32(len(pngDatas[i]))) // Size
		binary.Write(f, binary.LittleEndian, dataOffset)               // Offset
		dataOffset += uint32(len(pngDatas[i]))
	}

	// Image data
	for _, pd := range pngDatas {
		f.Write(pd)
	}

	return nil
}

type bytesBuffer struct {
	data []byte
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) Bytes() []byte {
	return b.data
}

func main() {
	icoPath := filepath.Join(os.Args[1], "pdf.ico")
	sizes := []int{16, 24, 32, 48, 64, 128, 256}

	if err := writeICO(icoPath, sizes); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Generated multi-size PDF icon: %s (sizes: %v)\n", icoPath, sizes)
}
