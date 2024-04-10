package Others

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FlagOptions struct {
	Help        bool
	OutFile     string
	InputFile   string
	Language    string
	Encryption  string
	KeyLength   int
	Obfuscation string
	Framework   int
	Sandbox     bool
	Unhook      bool
	Loading     string
}

func PrintVersion() {
	darkPluse := `
     _            _    _____  _                
     | |          | |  |  __ \| |               
   __| | __ _ _ __| | _| |__) | |_   _ ___  ___ 
  / _' |/ _' | '__| |/ /  ___/| | | | / __|/ _ \
 | (_| | (_| | |  |   <| |    | | |_| \__ \  __/
  \__,_|\__,_|_|  |_|\_\_|    |_|\__,_|___/\___| 

                                  author fdx_xdf
                                  version 1.0
                                  2024.04									
`
	fmt.Println(darkPluse)

}

func PrintUsage() {
	fmt.Println("Usage:")
	fmt.Println("  -h <help>: 显示帮助信息")
	fmt.Println("  -i <path>: 指定原始格式 Shellcode 的文件路径")
	fmt.Println("  -enc <encryption>: 设置 Shellcode 的加密方式 (默认为 'aes')")
	fmt.Println("  -lang <language>: 选择加载器的语言 (默认为 'c'，可选值: c)")
	fmt.Println("  -o <output>: 指定输出文件的名称 (默认为 'Program')")
	fmt.Println("  -k <keyLength>: 设置加密密钥的长度，aes下只能选择16,默认为16")
	fmt.Println("  -obf <obfuscation>: 选择混淆 Shellcode 的方式，以降低熵值 (默认为 'uuid'，可选值: uuid, words)")
	fmt.Println("  -f <framework>: 选择目标架构，32或64(默认为 64，即64位)")
	fmt.Println("  -sandbox <true/false>: 是否开启反沙箱模式 (默认为 'false'，即不开启)")
	fmt.Println("  -unhook <true/false>: 是否使用 unhook 模式 (默认为 'false'，即使用系统调用)")
	fmt.Println("  -loading <loadingTechnique>: 选择 Shellcode 的加载方式 (默认为 'fiber'，可选值: callback, fiber, earlybird)")
}

func PrintKeyDetails(key string) {
	for i, b := range key {
		// decimalValue := int(b)
		hexValue := fmt.Sprintf("%02x", b)
		fmt.Printf("0x%s", hexValue)
		if i < len(key)-1 {
			fmt.Printf(", ")
		}
	}

	fmt.Printf("\n\n")
}

// 检查AES加密格式
func DetectNotification(key int) int {
	logger := log.New(os.Stderr, "[!] ", 0)
	keyNotification := 0
	switch key {
	case 16:
		keyNotification = 128
	case 24:
		keyNotification = 192
	case 32:
		keyNotification = 256
	default:
		logger.Fatal("Initial Error, valid AES key not found\n")
	}

	return keyNotification
}

func SaveTamplate2File(filename string, tamplate string) {
	// Open a file for writing. If the file doesn't exist, it will be created.
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close() // Close the file when the function exits

	// Write the variable value to the file
	_, err = fmt.Fprintln(file, tamplate)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

}

func Build(options *FlagOptions, outfile string, framework int) {
	outexe := getOutfileName(outfile)
	// 执行编译命令
	switch framework {
	case 32:
		switch strings.ToLower(options.Encryption) {
		case "aes":
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				cmd := exec.Command("gcc", "-mwindows", "-m32", "-o3", "-o", outexe, outfile, "sys_32.c", "aes.c", "-s", "-masm=intel", "-lrpcrt4")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			case "words":
				cmd := exec.Command("gcc", "-mwindows", "-m32", "-o3", "-o", outexe, outfile, "sys_32.c", "aes.c", "-s", "-masm=intel")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			}
		case "xor":
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				cmd := exec.Command("gcc", "-mwindows", "-m32", "-o3", "-o", outexe, outfile, "sys_32.c", "-s", "-masm=intel", "-lrpcrt4")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			case "words":
				cmd := exec.Command("gcc", "-mwindows", "-m32", "-o3", "-o", outexe, outfile, "sys_32.c", "-s", "-masm=intel")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			}
		}
	case 64:
		switch strings.ToLower(options.Encryption) {
		case "aes":
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				cmd := exec.Command("gcc", "-mwindows", "-m64", "-o3", "-o", outexe, outfile, "sys_64.c", "aes.c", "-s", "-masm=intel", "-lrpcrt4")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			case "words":
				cmd := exec.Command("gcc", "-mwindows", "-m64", "-o3", "-o", outexe, outfile, "sys_64.c", "aes.c", "-s", "-masm=intel")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			}
		case "xor":
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				cmd := exec.Command("gcc", "-mwindows", "-m64", "-o3", "-o", outexe, outfile, "sys_64.c", "-s", "-masm=intel", "-lrpcrt4")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			case "words":
				cmd := exec.Command("gcc", "-mwindows", "-m64", "-o3", "-o", outexe, outfile, "sys_64.c", "-s", "-masm=intel")
				// 执行命令并等待其完成
				err := cmd.Run()
				if err != nil {
					fmt.Println("编译失败:", err)
					return
				}
				fmt.Printf("编译成功: " + outexe)
			}
		}
	default:
		fmt.Printf("请选择32位或者64位的操作系统")
	}
}

// 输出文件名
func getOutfileName(filename string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := base[0 : len(base)-len(ext)]
	return name + ".exe"
}
