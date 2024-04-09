一个用go编写的shellcode Packer

目前只实现了c的模板。

支持aes/xor加密，uuid/words混淆，支持间接syscall和unhook两种模式下的callback，fiber，earlybird三种加载方式。

间接sysacll使用了SysWhispers3的项目，链接：[klezVirus/SysWhispers3: SysWhispers on Steroids - AV/EDR evasion via direct system calls. (github.com)](https://github.com/klezVirus/SysWhispers3)

unhook使用了[自定义跳转函数的unhook方法 - root@Ev1LAsH ~ (killer.wtf)](https://killer.wtf/2022/01/19/CustomJmpUnhook.html)文中所讲述的方法，文中提到的github仓库https://github.com/trickster0/LdrLoadDll-Unhooking只实现了64位下的demo，我在[fdx-xdf/LdrLoadDll-Unhooking-x86-x64 (github.com)](https://github.com/fdx-xdf/LdrLoadDll-Unhooking-x86-x64)完善了32位和64位通用的一段代码。

使用方法：

```
Usage:
  -i <path>: 原始格式 Shellcode 的路径
  -enc <encryption>: Shellcode加密方式 (默认: aes)
  -lang <language>: 加载器的语言 (默认: c)
  -o <output>: 输出文件 (默认: Program)
  -k <keyLength>: 加密的密钥长度 (默认: 16)
  -obf <obfuscation>: 混淆Shellcode以降低熵值 (默认: uuid)
  -f <framework>: 目标架构32位还是64位
  -sandbox <true/false>: 是否开启反沙箱模式 (默认: true)
  -unhook <true/false>: 是否开启unhook模式 (默认: false,使用间接syscall加载)
  -loading <loadingTechnique>: 请选择加载方式，支持callback, fiber, earlybird (默认: fiber)
```

注意：syscall下的earlybird方式由于某些bug并没有使用间接syscall方式加载，尽量不要使用。

目前实现效果如下：

微步云沙箱无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1711596621444-4b4ab40f-7327-481f-a5f8-ca2d39330db6.png#averageHue=%23a0dcba&clientId=u723e99f6-9ffc-4&from=paste&height=911&id=u10f5a780&originHeight=1367&originWidth=2549&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=218236&status=done&style=none&taskId=u85e7150f-15a5-4768-a501-f4ea03a3050&title=&width=1699.3333333333333)

360（未开核晶）：无检出

![image](https://github.com/fdx-xdf/goPacker/assets/117912115/c3dcf083-609e-4b55-87c1-8311e5d28a40)

火绒：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712452727509-f3c2d4b3-90ab-448d-9335-d8ac90a3a2a3.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_1125%2Climit_0)

360（开启核晶）：无检出（使用syscall和unhook两种方式生成的exe均成功绕过核晶）

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712553684319-6e2573f1-7d58-4c36-9f92-4dba958a67f5.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_1125%2Climit_0)
to do list:

- go模板
- 更多加密算法
- 分离加载
- ~~- unhook~~
- .....
