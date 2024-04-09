一个用go编写的shellcode Packer

目前只实现了c的模板

支持aes/xor加密，uuid/words混淆，间接syscall下支持callback和fiber两种加载方式，unhook下支持callback，fiber，earlybird三种加载方式

目前实现效果如下：

微步云沙箱无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1711596621444-4b4ab40f-7327-481f-a5f8-ca2d39330db6.png#averageHue=%23a0dcba&clientId=u723e99f6-9ffc-4&from=paste&height=911&id=u10f5a780&originHeight=1367&originWidth=2549&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=218236&status=done&style=none&taskId=u85e7150f-15a5-4768-a501-f4ea03a3050&title=&width=1699.3333333333333)

360（未开核晶）：无检出

![image](https://github.com/fdx-xdf/goPacker/assets/117912115/c3dcf083-609e-4b55-87c1-8311e5d28a40)

火绒：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712452727509-f3c2d4b3-90ab-448d-9335-d8ac90a3a2a3.png#clientId=u990ef8ce-17ff-4&from=paste&height=413&id=uf773694c&originHeight=1493&originWidth=2560&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=267434&status=done&style=none&taskId=u6ef9bb21-ca36-407e-8485-d49cbc2d15d&title=&width=709)

360（开启核晶）：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712553684319-6e2573f1-7d58-4c36-9f92-4dba958a67f5.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_1125%2Climit_0)
to do list:

- go模板
- 更多加密算法
- ~~- unhook~~
- .....
