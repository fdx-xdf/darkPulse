package Converters

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func OriginalShellcode(inputFile string) []byte {
	fileContent, err := ioutil.ReadFile(inputFile)
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
