package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

// AesDecrypt AES-GCM解密
func AesDecrypt(ciphertext []byte) ([]byte, error) {
	key := GetKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// B64Encode Base64编码
func B64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// B64Decode Base64解码
func B64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
