package Converters

import (
	"MyPacker/Others"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func OriginalShellcode(options *Others.FlagOptions) []byte {
	fmt.Println("[+] 正在使用 sgn 工具进行编码\n")
	switch runtime.GOOS {
	case "windows":
		//windows下
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get the current working directory: %v", err)
		}
		dir1 := filepath.Join(dir, "T00ls", "sgn.exe")
		cmd := exec.Command(dir1, "-a", strconv.Itoa(options.Framework), "-i", options.InputFile)

		// 运行命令并等待它完成
		err = cmd.Run()
		if err != nil {
			log.Fatalf("Failed to execute command: %v", err)
		}
	case "darwin": // macOS 的 GOOS 标识符是 darwin
		// macOS 系统执行的命令
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get the current working directory: %v", err)
		}
		dir1 := filepath.Join(dir, "T00ls", "sgn")
		cmd := exec.Command(dir1, "-a", strconv.Itoa(options.Framework), "-i", options.InputFile)

		// 运行命令并等待它完成
		err = cmd.Run()
		if err != nil {
			log.Fatalf("Failed to execute command: %v", err)
		}
	}
	var file = options.InputFile + ".sgn"
	fileContent, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Filed to open inputFile", err)
		os.Exit(-1)
	}

	return []byte(fileContent)

}

func ShellcodeToHex(shellcode string) string {

	StringShellcode := strings.TrimSpace(string(shellcode))
	//将shellcode转换成hex格式
	hexShellcode := hex.EncodeToString([]byte(StringShellcode))
	return hexShellcode
}

// 将shellcode格式化
func FormattedHexShellcode(hexShellcode string) string {
	var builder strings.Builder
	for i := 0; i < len(hexShellcode); i += 2 {
		// Add "0x" prefix and then two hex digits.
		builder.WriteString("0x")
		builder.WriteString(hexShellcode[i : i+2])
		// If not the last pair, add comma and space.
		if i < len(hexShellcode)-2 {
			builder.WriteString(", ")
		}
	}
	return builder.String()
}

// 将dataset从[]string变成string
func FormattedDataset(dataset []string) string {
	var trimmedDataset []string
	for _, s := range dataset {
		trimmed := strings.TrimRight(s, "\r")
		trimmedDataset = append(trimmedDataset, trimmed)
	}
	datasetString := "\"" + strings.Join(trimmedDataset, "\", \"") + "\""
	return datasetString
}
