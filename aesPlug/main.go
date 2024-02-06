package aesplug

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

// encryptAES 使用AES算法对明文进行加密，并返回十六进制表示的密文字符串
func EncryptAES(key []byte, plaintext string) string {
	// 创建新的AES密码块
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
	}

	// 使用PKCS#7填充方式，获取明文填充后的长度
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padText := []byte{byte(padding)}
	padText = append(padText, bytes.Repeat([]byte{byte(padding)}, padding-1)...)

	// 进行填充
	plaintextBytes := []byte(plaintext)
	plaintextBytes = append(plaintextBytes, padText...)

	// 创建AES加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:aes.BlockSize])

	// 加密明文并将结果存储在tmpByteSlice中
	ciphertext := make([]byte, len(plaintextBytes))
	blockMode.CryptBlocks(ciphertext, plaintextBytes)

	// 将加密后的字节切片转换为十六进制字符串并返回
	return hex.EncodeToString(ciphertext)
}

// decryptAES 使用AES算法对密文进行解密，并返回解密后的明文
func DecryptAES(key []byte, ciphertext string) string {
	// 将十六进制表示的密文转换为字节切片
	ciphertextBytes, _ := hex.DecodeString(ciphertext)

	// 创建新的AES密码块
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
	}

	// 创建AES解密模式
	blockMode := cipher.NewCBCDecrypter(block, key[:aes.BlockSize])

	// 解密密文并将结果存储在plaintext中
	plaintext := make([]byte, len(ciphertextBytes))
	blockMode.CryptBlocks(plaintext, ciphertextBytes)

	// 去除填充
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]

	return string(plaintext)
}
