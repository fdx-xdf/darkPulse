一个用go编写的shellcode Packer

目前只实现了c的模板

支持aes/xor加密，uuid/words混淆，间接syscall调用windows api，callback和fiber两种加载方式

目前实现效果如下：

微步云沙箱无检出

![image](https://github.com/fdx-xdf/goPacker/assets/117912115/eab4801b-5a55-4211-b72e-4c51acd20886)


360（未开核晶）：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1711691599173-9249fbf7-9a87-4175-9b67-b3303315cf90.png#averageHue=%23eef4e8&clientId=u6a213678-1bda-4&from=paste&height=613&id=u57fad8a0&originHeight=920&originWidth=1704&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=653395&status=done&style=none&taskId=ue8886f9f-69d5-4f73-a7de-2e1b4b44cbe&title=&width=1136)

火绒：无检出

![image.png](https://cdn.nlark.com/yuque/0/2024/png/40360538/1711596362835-764a2654-c5c3-4756-8d14-06a78cef05f7.png#averageHue=%23fbf8f6&clientId=u723e99f6-9ffc-4&from=paste&height=563&id=u6518f191&originHeight=845&originWidth=1540&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=89947&status=done&style=none&taskId=u135de88f-fd73-4c4a-b967-27d473a7442&title=&width=1026.6666666666667)

to do list:

- go模板
- 更多加密算法
- unhook
- .....
