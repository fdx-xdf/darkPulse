package Encrypt

import (
	"MyPacker/Others"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// 生成随机密钥
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// 随机字符串
func GenerateRandomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// BytesToUUIDs_C 将字节slice分割成多个16字节的组，并转换成UUID格式的字符串切片
func BytesToUUIDs_C(b []byte) ([]string, error) {
	var uuids []string
	chunkSize := 16

	for len(b) > 0 {
		// 如果剩余的字节不足16字节，则用0补足
		if len(b) < chunkSize {
			padding := make([]byte, chunkSize-len(b))
			b = append(b, padding...)
		}

		// 截取16字节的组
		chunk := b[:chunkSize]
		b = b[chunkSize:]

		// 将字节转换为十六进制字符串
		hexString := hex.EncodeToString(chunk)

		// 格式化UUID字符串
		uuid := fmt.Sprintf("%s%s%s%s-%s%s-%s%s-%s-%s",
			hexString[6:8],
			hexString[4:6],
			hexString[2:4],
			hexString[0:2],
			hexString[10:12],
			hexString[8:10],
			hexString[14:16],
			hexString[12:14],
			hexString[16:20],
			hexString[20:32])

		uuids = append(uuids, uuid)
	}

	return uuids, nil
}

// BytesToUUIDs_RUST 将字节slice分割成多个16字节的组，并转换成UUID格式的字符串切片
// 现在前半段是UUID，后半段是words，为了加快编译速度
func BytesToUUIDs_RUST(b []byte) ([]string, string, string, error) {
	// 确保前半段长度是16的整数倍
	totalLength := len(b)
	portionLen := totalLength / 10
	uuidLen := totalLength - portionLen

	// 调整uuidLen使其为16的倍数
	if remainder := uuidLen % 16; remainder != 0 {
		uuidLen += 16 - remainder
	}

	uuidPart := b[:uuidLen]
	wordsPart := b[uuidLen:]

	var uuids []string
	chunkSize := 16

	for len(uuidPart) > 0 {
		// 如果剩余的字节不足16字节，则用0补足
		if len(uuidPart) < chunkSize {
			padding := make([]byte, chunkSize-len(uuidPart))
			uuidPart = append(uuidPart, padding...)
		}

		// 截取16字节的组
		chunk := uuidPart[:chunkSize]
		uuidPart = uuidPart[chunkSize:]

		// 将字节转换为十六进制字符串
		hexString := hex.EncodeToString(chunk)

		// 格式化UUID字符串
		uuid := fmt.Sprintf("%s-%s-%s-%s-%s",
			hexString[0:8],
			hexString[8:12],
			hexString[12:16],
			hexString[16:20],
			hexString[20:32])

		uuids = append(uuids, uuid)
	}
	//调用python脚本，获取dataset和words

	err := ioutil.WriteFile("T00ls\\enc.bin", wordsPart, 0644)
	if err != nil {
		panic(err)
	}
	dir, err := os.Getwd()
	dir1 := filepath.Join(dir, "T00ls", "Shellcode-to-English.py")
	dir2 := filepath.Join(dir, "T00ls", "enc.bin")
	words_path := filepath.Join(dir, "T00ls", "words.txt")
	dataset_path := filepath.Join(dir, "T00ls", "dataset.txt")
	cmd := exec.Command("python", dir1, dir2)
	// 捕获标准输出和标准错误
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		fmt.Println("编译失败:", err)
		// 获取标准错误的内容
		stderrString := stderr.String()
		if stderrString != "" {
			fmt.Println("标准错误:", stderrString)
		}
	}
	words, err := ioutil.ReadFile(words_path)
	if err != nil {
		log.Fatal(err)
	}
	dataset, err := ioutil.ReadFile(dataset_path)
	if err != nil {
		log.Fatal(err)
	}
	return uuids, string(words), string(dataset), nil
}

func HexStringToBytes(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// 混淆操作
func Obfuscation(options *Others.FlagOptions, shellcodeString string) (string, string, string) {
	switch strings.ToLower(options.Obfuscation) {

	case "uuid":
		var uuids []string
		var words string
		var dataset string
		bytes, _ := HexStringToBytes(shellcodeString)
		var err error
		switch strings.ToLower(options.Language) {
		case "c":
			uuids, err = BytesToUUIDs_C([]byte(bytes))
			if err != nil {
				fmt.Println("Error:", err)
			}
		case "rust":
			uuids, words, dataset, err = BytesToUUIDs_RUST([]byte(bytes))
			if err != nil {
				fmt.Println("Error:", err)
			}
		}
		var uuidsString string
		for _, uuid := range uuids {
			uuidsString += "\"" + uuid + "\","
		}
		return uuidsString, words, dataset
	case "words":
		switch strings.ToLower(options.Language) {

		case "c":
			//调用python脚本，获取dataset和words
			decoded, err := hex.DecodeString(shellcodeString)
			if err != nil {
				panic(err)
			}

			err = ioutil.WriteFile("T00ls\\enc.bin", decoded, 0644)
			if err != nil {
				panic(err)
			}
			dir, err := os.Getwd()
			dir1 := filepath.Join(dir, "T00ls", "Shellcode-to-English.py")
			dir2 := filepath.Join(dir, "T00ls", "enc.bin")
			words_path := filepath.Join(dir, "T00ls", "words.txt")
			dataset_path := filepath.Join(dir, "T00ls", "dataset.txt")
			cmd := exec.Command("python", dir1, dir2)
			// 捕获标准输出和标准错误
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			if err != nil {
				fmt.Println("编译失败:", err)
				// 获取标准错误的内容
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("标准错误:", stderrString)
				}
				return "", "", ""
			}
			words, err := ioutil.ReadFile(words_path)
			if err != nil {
				log.Fatal(err)
			}
			dataset, err := ioutil.ReadFile(dataset_path)
			if err != nil {
				log.Fatal(err)
			}

			//fmt.Println("[+] Generated dataset" + string(dataset) + "\n")
			//fmt.Println("[+] Generated words:" + string(words) + "\n")
			return "", string(words), string(dataset)
		case "rust":
			var uuids []string
			var words string
			var dataset string
			bytes, _ := HexStringToBytes(shellcodeString)
			var err error
			uuids, words, dataset, err = BytesToUUIDs_RUST([]byte(bytes))
			if err != nil {
				fmt.Println("Error:", err)
			}

			var uuidsString string
			for _, uuid := range uuids {
				uuidsString += "\"" + uuid + "\","
			}
			return uuidsString, words, dataset
		}

	}
	return "", "", ""
}
