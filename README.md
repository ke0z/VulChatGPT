# VulChatGPT

An IDA PRO plugin to help in finding vulnerabilites in binaries.

Use IDA PRO HexRays decompiler with OpenAI(ChatGPT) to find possible vulnerabilities in binaries 

Disclaimer, possible replies while trying to find binary vulnerabilites using an AI may lead to false positives, however it has worked in many CTFs I have worked on (simple/medium ... some hard)

### Inspired by Gepetto : https://github.com/JusticeRage/Gepetto

## Install:

Drop python script on IDA Pro Plugin location.

## To Use:

Right click on decompiled code , select "Find possible vulnerability in function"

![image](https://user-images.githubusercontent.com/118329900/209662066-8eb6fa58-334f-4f5f-b3fd-534baf8bca62.png)

![image](https://user-images.githubusercontent.com/118329900/209662336-336257d8-2524-4879-a5ce-3d4acc3808cb.png)

### Updated with create sample python exploit (Sometime Good, Sometime Sh!t)

![image](https://user-images.githubusercontent.com/118329900/211160190-d077a4b3-f49f-4696-b618-134ae10a6d9a.png)

### Updated with Gepetto's rename and explain functions 

![image](https://user-images.githubusercontent.com/118329900/220962130-3b82708b-f228-4053-a85d-342c5df9eea4.png)



## ISSUES
### Large functions dont work due to size restriction on OpenAI
### Well do a little bit of static, rename variables/functions, create structs if need be add some FLIRT  ... i mean help your AI out :)
### False +ves (wuuueh!!)
