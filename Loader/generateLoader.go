package Loader

import (
	"MyPacker/Converters"
	"MyPacker/Others"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateAndWriteTemplateToFile(options *Others.FlagOptions, EncryptShellcode string, key string, iv string, uuidString string, words string, datasetString string) string {
	var file_extension = ""
	switch options.Language {
	case "c":
		file_extension = options.OutFile + ".c"
	case "rust":
		file_extension = "main.rs"
	default:
		println("选择语言错误\n")
		os.Exit(1)
	}
	fmt.Println("[+] 正在为您生成模板文件: " + file_extension + "\n")
	outfile := options.OutFile
	EncryptShellcode = Converters.FormattedHexShellcode(EncryptShellcode)
	switch strings.ToLower(options.Language) {
	case "c":
		dir, _ := os.Getwd()
		outfile = outfile + ".c"
		dir1 := filepath.Join(dir, "C_Template", outfile)
		switch options.Unhook {
		case false:
			//判断反沙箱
			switch options.Sandbox {
			case true:
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
			default:
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", "")
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", "")
			}
			//目标架构
			switch options.Framework {
			case 64:
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
			case 32:
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
			}
			switch strings.ToLower(options.Encryption) {
			case "xor":
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACR_OBFUSCATION", __c__uuid)
					__c__syscall__xor = fmt.Sprintf(__c__syscall__xor, uuidString, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
					case "fiber":
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
					case "earlybird":
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__syscall__xor)
				case "words":
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACR_OBFUSCATION", __c__words)
					__c__syscall__xor = fmt.Sprintf(__c__syscall__xor, datasetString, words, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
					case "fiber":
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
					case "earlybird":
						__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__syscall__xor)
				}
			case "aes":
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACR_OBFUSCATION", __c__uuid)
					__c__syscall__aes = fmt.Sprintf(__c__syscall__aes, uuidString, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
					case "fiber":
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
					case "earlybird":
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__syscall__aes)
				case "words":
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACR_OBFUSCATION", __c__words)
					__c__syscall__aes = fmt.Sprintf(__c__syscall__aes, datasetString, words, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
					case "fiber":
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
					case "earlybird":
						__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__syscall__aes)
				}
			}
		case true:
			switch options.Sandbox {
			case true:
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
			default:
				__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", "")
				__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", "")
			}
			switch strings.ToLower(options.Encryption) {
			case "xor":
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACR_OBFUSCATION", __c__uuid)
					__c__unhook__xor = fmt.Sprintf(__c__unhook__xor, uuidString, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook_callback)
					case "fiber":
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook__fiber)
					case "earlybird":
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__unhook__xor)
				case "words":
					__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACR_OBFUSCATION", __c__words)
					__c__unhook__xor = fmt.Sprintf(__c__unhook__xor, datasetString, words, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook_callback)
					case "fiber":
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook__fiber)
					case "earlybird":
						__c__unhook__xor = strings.ReplaceAll(__c__unhook__xor, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__unhook__xor)
				}
			case "aes":
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACR_OBFUSCATION", __c__uuid)
					__c__unhook__aes = fmt.Sprintf(__c__unhook__aes, uuidString, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook_callback)
					case "fiber":
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook__fiber)
					case "earlybird":
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__unhook__aes)
				case "words":
					__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACR_OBFUSCATION", __c__words)
					__c__unhook__aes = fmt.Sprintf(__c__unhook__aes, datasetString, words, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						//生成模板
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook_callback)
					case "fiber":
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook__fiber)
					case "earlybird":
						__c__unhook__aes = strings.ReplaceAll(__c__unhook__aes, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
					}
					//写文件
					Others.SaveTemplateToFile(dir1, __c__unhook__aes)
				}

			}

		}
	case "rust":
		dir, _ := os.Getwd()
		dir1 := filepath.Join(dir, "Rust_Template", "src", "main.rs")
		outfile = outfile + ".rs"
		switch options.Unhook {
		case true:
			switch options.Sandbox {
			case true:
				__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_ANTI_SANDBOX", __rust__sandbox)
			default:
				__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_ANTI_SANDBOX", "")
			}
			switch strings.ToLower(options.Encryption) {
			case "xor":
				__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_DECRYPT", __rust__xor)
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_OBFUSCATION", __rust__uuid)
					__rust__unhook = fmt.Sprintf(__rust__unhook, uuidString, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__callback)
					case "fiber":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__fiber)
					case "earlybird":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__earlybird)
					}
					Others.SaveTemplateToFile(dir1, __rust__unhook)
				case "words":
					__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_OBFUSCATION", __rust__words)
					__rust__unhook = fmt.Sprintf(__rust__unhook, datasetString, words, key)
					switch strings.ToLower(options.Loading) {
					case "callback":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__callback)
					case "fiber":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__fiber)
					case "earlybird":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__earlybird)
					}
					Others.SaveTemplateToFile(dir1, __rust__unhook)
				}
			case "aes":
				__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_DECRYPT", __rust__aes)
				switch strings.ToLower(options.Obfuscation) {
				case "uuid":
					__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_OBFUSCATION", __rust__uuid)
					__rust__unhook = fmt.Sprintf(__rust__unhook, uuidString, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__callback)
					case "fiber":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__fiber)
					case "earlybird":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__earlybird)
					}

					Others.SaveTemplateToFile(dir1, __rust__unhook)
				case "words":
					__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_OBFUSCATION", __rust__words)
					__rust__unhook = fmt.Sprintf(__rust__unhook, datasetString, words, key, iv)
					switch strings.ToLower(options.Loading) {
					case "callback":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__callback)
					case "fiber":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__fiber)
					case "earlybird":
						__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACE_Loading_Technique", __rust__unhook__earlybird)
					}
					Others.SaveTemplateToFile(dir1, __rust__unhook)
				}
			}
		case false:
			fmt.Println("暂不支持此种加载方式")
			os.Exit(-1)
		}

	}
	return outfile
}
