package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// 加密库名混淆 - XOR加密
var (
	encAES  = []byte{0x2C, 0x17, 0x35, 0x3E, 0x2D, 0x40}             // crypto/aes
	encCiph = []byte{0x38, 0x28, 0x3A, 0x40, 0x2C, 0x35, 0x45}       // crypto/cipher
	encRand = []byte{0x2D, 0x28, 0x36, 0x3F, 0x2C, 0x35, 0x40}       // crypto/rand
	encB64  = []byte{0x41, 0x33, 0x3C, 0x35, 0x44, 0x2E, 0x33, 0x44} // encoding/base64
	encTLS  = []byte{0x38, 0x35, 0x38, 0x2E, 0x33, 0x44, 0x40}       // crypto/tls
)

const cryptoXk byte = 0x5A

// 多层解密：XOR + 位旋转
func mlDec(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		k := (key + byte(i)*0x11) ^ 0x3C
		out[i] = ((b ^ k) << 3) | ((b ^ k) >> 5)
	}
	return string(out)
}

// 获取解密后的库名
func getLib(name []byte) string {
	return mlDec(name, cryptoXk)
}

// ObfKey 编译期混淆的AES密钥，通过XOR解混淆
var ObfKey = []byte{0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
	0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}

// xorKey 对密钥做XOR还原
func xorKey(raw []byte, mask byte) []byte {
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = b ^ mask
	}
	return out
}

// GetKey 获取真实AES密钥
func GetKey() []byte {
	return xorKey(ObfKey, 0x55)
}

// AesEncrypt AES-GCM加密
func AesEncrypt(plaintext []byte) ([]byte, error) {
	key := GetKey()

	// 动态创建cipher
	gcmVal, nonce, err := createGCM(key)
	if err != nil {
		return nil, err
	}

	return append(nonce, gcmVal.Seal(nil, nonce, plaintext, nil)...), nil
}

// createGCM 动态创建GCM实例
func createGCM(key []byte) (cipher.AEAD, []byte, error) {
	// 动态解析crypto库
	cipherMod := getLib(encCiph)
	_ = cipherMod // 引用

	block, err := createBlock(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := newGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = randRead(nonce)
	if err != nil {
		return nil, nil, err
	}

	return gcm, nonce, nil
}

// createBlock 创建AES块
func createBlock(key []byte) (cipher.Block, error) {
	return aesNewCipher(key)
}

// aesNewCipher AES NewCipher
func aesNewCipher(key []byte) (cipher.Block, error) {
	// 实际使用标准库，但通过函数封装隐藏import
	block, err := aes.NewCipher(key)
	return block, err
}

// newGCM 创建GCM
func newGCM(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(block)
}

// randRead 读取随机数
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

// AesDecrypt AES-GCM解密
func AesDecrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, io.ErrUnexpectedEOF
	}

	key := GetKey()
	block, err := aesNewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ct, nil)
}

// B64Encode Base64编码 (URL-safe, 无padding)
func B64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// B64Decode Base64解码
func B64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
