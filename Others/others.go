package Others

import (
	"bytes"
	"fmt"
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
	Debug       bool
}

func PrintVersion() {
	fmt.Println("      _            _    _____       _          ")
	fmt.Println("     | |          | |  |  __ \\     | |         ")
	fmt.Println("   __| | __ _ _ __| | _| |__) |   _| |___  ___ ")
	fmt.Println("  / _` |/ _` | '__| |/ /  ___/ | | | / __|/ _ \\")
	fmt.Println(" | (_| | (_| | |  |   <| |   | |_| | \\__ \\  __/")
	fmt.Println("  \\__,_|\\__,_|_|  |_|\\_\\_|    \\__,_|_|___/\\___|")
	fmt.Println("                                               ")
	fmt.Println("                    author fdx_xdf             ")
	fmt.Println("                    version 2.1                ")
	fmt.Println("                    2024.07                    ")
}

func PrintUsage() {
	fmt.Println("Usage:")
	fmt.Println("  -h <help>: 显示帮助信息")
	fmt.Println("  -i <path>: 指定原始格式 Shellcode 的文件路径")
	fmt.Println("  -enc <encryption>: 设置 Shellcode 的加密方式 (默认为 'aes')")
	fmt.Println("  -lang <language>: 选择加载器的语言 (默认为 'c'，可选值: c,rust)")
	fmt.Println("  -o <output>: 指定输出文件的名称 (默认为 'Program')")
	fmt.Println("  -k <keyLength>: 设置加密密钥的长度，aes下只能选择16,默认为16")
	fmt.Println("  -obf <obfuscation>: 选择混淆 Shellcode 的方式，以降低熵值 (默认为 'uuid'，可选值: uuid, words)")
	fmt.Println("  -f <framework>: 选择目标架构，32或64(默认为 64，即64位)")
	fmt.Println("  -sandbox <true/false>: 是否开启反沙箱模式 (默认为 'false'，即不开启)")
	fmt.Println("  -unhook <true/false>: 是否使用 unhook 模式 (默认为 'false'，即使用系统调用)")
	fmt.Println("  -loading <loadingTechnique>: 选择 Shellcode 的加载方式 (默认为 'callback'，可选值: callback, fiber, earlybird)")
	fmt.Println("  -debug  <true/false>: 是否打印shellcode中间加密/混淆过程(默认为 'false'，即不打印)")
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
//func DetectNotification(key int) int {
//	logger := log.New(os.Stderr, "[!] ", 0)
//	keyNotification := 0
//	switch key {
//	case 16:
//		keyNotification = 128
//	case 24:
//		keyNotification = 192
//	case 32:
//		keyNotification = 256
//	default:
//		logger.Fatal("Initial Error, valid AES key not found\n")
//	}
//
//	return keyNotification
//}

func SaveTemplateToFile(filename string, template string) {
	// 确保目录存在
	dir := filepath.Dir(filename)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Println("创建目录时出错:", err)
		return
	}

	// 打开一个文件进行写入。如果文件不存在，将会创建该文件。
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("创建文件时出错:", err)
		return
	}
	defer file.Close() // 在函数退出时关闭文件

	// 将变量值写入文件
	_, err = fmt.Fprintln(file, template)
	if err != nil {
		fmt.Println("写入文件时出错:", err)
		return
	}
}

// MoveAndRenameFile 移动并重命名文件
func MoveAndRenameFile(srcPath, dstPath string) error {
	err := os.Rename(srcPath, dstPath)
	if err != nil {
		return fmt.Errorf("移动并重命名文件时出错: %w", err)
	}
	return nil
}

func Build(options *FlagOptions, outfile string, framework int) {
	outexe := getOutfileName(outfile)
	// 执行编译命令
	switch strings.ToLower(options.Language) {
	case "c":
		switch framework {
		case 32:
			dir, _ := os.Getwd()
			outfile = outfile
			srcdir := filepath.Join(dir, "C_Template", outfile)
			sysdir := filepath.Join(dir, "C_Template", "sys_32.c")
			cmd := exec.Command("gcc", "-mwindows", "-m32", "-o", outexe, srcdir, sysdir, "-s", "-masm=intel", "-lrpcrt4")
			// 执行命令并等待其完成
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("编译失败:", err)
				// 获取标准错误的内容
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("标准错误:", stderrString)
				}
				return
			}
			fmt.Printf("[+] 编译成功: " + outexe)
		case 64:
			dir, _ := os.Getwd()
			srcdir := filepath.Join(dir, "C_Template", outfile)
			sysdir := filepath.Join(dir, "C_Template", "sys_64.c")
			cmd := exec.Command("gcc", "-mwindows", "-m64", "-o", outexe, srcdir, sysdir, "-s", "-masm=intel", "-lrpcrt4")
			// 执行命令并等待其完成
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("编译失败:", err)
				// 获取标准错误的内容
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("标准错误:", stderrString)
				}
				return
			}
			fmt.Printf("[+] 编译成功: " + outexe)
		default:
			fmt.Printf("请选择32位或者64位的操作系统")
		}
	case "rust":
		os.Setenv("RUSTFLAGS", "-Z threads=18")
		dir, _ := os.Getwd()
		dir1 := filepath.Join(dir, "Rust_Template", "Cargo.toml")
		switch options.Framework {
		case 64:
			cmd := exec.Command("cargo", "build", "--manifest-path", dir1, "--release")
			// 执行命令并等待其完成
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("编译失败:", err)
				// 获取标准错误的内容
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("标准错误:", stderrString)
				}
				return
			}
			fmt.Println("[+] 正在为您移动可执行文件\n")
			dir, _ := os.Getwd()
			dir1 := filepath.Join(dir, "Rust_Template", "target", "release", "Unhook.exe")
			dstPath := filepath.Join(dir, outexe)
			err = MoveAndRenameFile(dir1, dstPath)
			if err != nil {
				fmt.Println("移动并重命名文件时出错:", err)
			} else {
				fmt.Printf("[+] 编译成功: " + outexe)
			}
		case 32:
			cmd := exec.Command("cargo", "build", "--manifest-path", dir1, "--release", "--target=i686-pc-windows-gnu")
			// 执行命令并等待其完成
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("编译失败:", err)
				// 获取标准错误的内容
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("标准错误:", stderrString)
				}
				return
			}
			fmt.Println("[+] 正在为您移动可执行文件\n")
			dir, _ := os.Getwd()
			dir1 := filepath.Join(dir, "Rust_Template", "target", "i686-pc-windows-gnu", "release", "Unhook.exe")
			dstPath := filepath.Join(dir, outexe)
			err = MoveAndRenameFile(dir1, dstPath)
			if err != nil {
				fmt.Println("移动并重命名文件时出错:", err)
			} else {
				fmt.Printf("[+] 编译成功: " + outexe)
			}

		}
	default:
		println("指定语言错误")
		os.Exit(-1)

	}

}

// 输出文件名
func getOutfileName(filename string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := base[0 : len(base)-len(ext)]
	return name + ".exe"
}
