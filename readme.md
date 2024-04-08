一个用go编写的shellcode Packer

目前只实现了c的模板

支持aes/xor加密，uuid/words混淆，间接syscall下支持callback和fiber两种加载方式，unhook下支持callback，fiber，earlybird三种加载方式

目前实现效果如下：

微步云沙箱无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1711596621444-4b4ab40f-7327-481f-a5f8-ca2d39330db6.png#averageHue=%23a0dcba&clientId=u723e99f6-9ffc-4&from=paste&height=911&id=u10f5a780&originHeight=1367&originWidth=2549&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=218236&status=done&style=none&taskId=u85e7150f-15a5-4768-a501-f4ea03a3050&title=&width=1699.3333333333333)

360（未开核晶）：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712540772208-56ad496e-d10f-4509-8d5c-be5bca8aeda1.png#clientId=u8b198af0-b954-4&from=paste&height=907&id=u3224cbb3&originHeight=1360&originWidth=2201&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=711812&status=done&style=none&taskId=ue4289f80-7d64-4c82-87ab-558045b9d4d&title=&width=1467.3333333333333)

火绒：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712452727509-f3c2d4b3-90ab-448d-9335-d8ac90a3a2a3.png#clientId=u990ef8ce-17ff-4&from=paste&height=413&id=uf773694c&originHeight=1493&originWidth=2560&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=267434&status=done&style=none&taskId=u6ef9bb21-ca36-407e-8485-d49cbc2d15d&title=&width=709)

360（开启核晶）：无检出
![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1712541933105-d742adb2-8f0c-473e-8b35-42b03bc5c6f7.png#clientId=u8b198af0-b954-4&from=paste&height=907&id=udd3a6cab&originHeight=1360&originWidth=2201&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=1233314&status=done&style=none&taskId=uc27fc9bc-28b3-4029-b272-3039a40bae8&title=&width=1467.3333333333333)
to do list:

- go模板
- 更多加密算法
~~- unhook~~
- .....