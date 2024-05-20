package Encrypt

import (
	"MyPacker/Others"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// 异或加密
func XOREncryption(shellcode []byte, key string) []byte {
	encrypted := make([]byte, len(shellcode))
	keyLen := len(key)

	for i := 0; i < len(shellcode); i++ {
		encrypted[i] = shellcode[i] ^ key[i%keyLen]
	}

	return encrypted
}

// AES中填充操作
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// AES加密
func AESEncryption(key string, iv string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// Apply PKCS7 padding to ensure plaintext length is a multiple of the block size
	paddedData := PKCS7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))

	// Create a new CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
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
func BytesToUUIDs_RUST(b []byte) ([]string, error) {
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
		uuid := fmt.Sprintf("%s-%s-%s-%s-%s",
			hexString[0:8],
			hexString[8:12],
			hexString[12:16],
			hexString[16:20],
			hexString[20:32])

		uuids = append(uuids, uuid)
	}

	return uuids, nil
}

// 加密函数
func Encryption(shellcodeBytes []byte, encryption string, keyLength int) (string, string, string) {
	//生成xor随机密钥
	switch encryption {
	case "xor":
		key := GenerateRandomString(keyLength)
		fmt.Printf("[+] Generated XOR key: ")
		Others.PrintKeyDetails(key)
		XorShellcode := XOREncryption(shellcodeBytes, key)
		hexXorShellcode := hex.EncodeToString((XorShellcode))
		//fomrattedXorShellcode := Converters.FormattedHexShellcode(string(hexXorShellcode))
		return hexXorShellcode, key, ""
	case "aes":
		key := GenerateRandomString(16)
		iv := GenerateRandomString(16)
		fmt.Printf("[+] Generated AES key: ")
		Others.PrintKeyDetails(key)
		fmt.Printf("[+] Generated IV (16-byte): ")
		Others.PrintKeyDetails(iv)
		keyNotification := Others.DetectNotification(keyLength)
		fmt.Printf("[+] Using AES-%d-CBC encryption\n\n", keyNotification)
		AESShellcode, _ := AESEncryption(key, iv, shellcodeBytes)
		hexXorShellcode := hex.EncodeToString(AESShellcode)

		return string(hexXorShellcode), key, iv
	}
	return "", "", ""
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
		bytes, _ := HexStringToBytes(shellcodeString)
		var err error
		switch strings.ToLower(options.Language) {
		case "c":
			uuids, err = BytesToUUIDs_C([]byte(bytes))
			if err != nil {
				fmt.Println("Error:", err)
			}
		case "rust":
			uuids, err = BytesToUUIDs_RUST([]byte(bytes))
			if err != nil {
				fmt.Println("Error:", err)
			}
		}
		var uuidsString string
		for _, uuid := range uuids {
			uuidsString += "\"" + uuid + "\","
		}
		return uuidsString, "", ""
	case "words":
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
	}
	return "", "", ""
}
