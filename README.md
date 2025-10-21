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



Adding OpenAI API Key

Windows (PowerShell)

Temporary (current PowerShell window only):

$env:OPENAI_API_KEY = "sk-your-key-here"
# (optional if you use a proxy/gateway)
$env:OPENAI_BASE_URL = "https://api.openai.com/v1"


Then launch IDA from the same window so it inherits the variable:

& "C:\Program Files\IDA Pro 9.0\idat64.exe"


Persistent (for your user account):

setx OPENAI_API_KEY "sk-your-key-here"
# optional:
setx OPENAI_BASE_URL "https://api.openai.com/v1"


➡️ Close PowerShell and restart IDA (apps only see new env vars on next start).

Check it:

[Environment]::GetEnvironmentVariable("OPENAI_API_KEY","User")

Windows (Command Prompt / cmd.exe)

Temporary (current cmd only):

set OPENAI_API_KEY=sk-your-key-here
set OPENAI_BASE_URL=https://api.openai.com/v1
"C:\Program Files\IDA Pro 9.0\idat64.exe"


Persistent (user env):

setx OPENAI_API_KEY "sk-your-key-here"
setx OPENAI_BASE_URL "https://api.openai.com/v1"


➡️ Restart IDA afterward.

Linux / macOS (bash/zsh)

Temporary (this shell only):

export OPENAI_API_KEY="sk-your-key-here"
export OPENAI_BASE_URL="https://api.openai.com/v1"
idat64


Persistent:
Add to your shell profile and reload it (or open a new terminal):

# bash: ~/.bashrc or ~/.profile
# zsh:  ~/.zshrc
export OPENAI_API_KEY="sk-your-key-here"
export OPENAI_BASE_URL="https://api.openai.com/v1"
