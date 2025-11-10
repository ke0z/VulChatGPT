# BinAIVulHunter

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

# BinAIVulHunter - AI-Powered Vulnerability Analysis Plugin for IDA Pro

[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.0+-green.svg)](https://www.hex-rays.com/products/ida/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

BinAIVulHunter is an advanced IDA Pro plugin that leverages multiple AI providers (OpenAI GPT, Google Gemini, and Ollama) to perform intelligent vulnerability analysis, code explanation, and security assessment of decompiled functions.

## 🚀 Features

- **Multi-AI Provider Support**: Choose between OpenAI GPT, Google Gemini, or Ollama
- **Vulnerability Detection**: Automated scanning based on CWE (Common Weakness Enumeration) taxonomy
- **Code Explanation**: AI-powered analysis and explanation of decompiled functions
- **Variable Renaming**: Intelligent suggestions for better variable and function names
- **Batch Processing**: Scan all functions in a binary with memory management
- **CWE Reference Integration**: Built-in CWE lookup and detailed vulnerability categorization
- **Headless Mode**: Command-line support for automated analysis
- **Local AI Support**: Privacy-focused analysis with Ollama (no cloud dependencies)

## 📋 Table of Contents

- [Installation](#-installation)
- [AI Provider Setup](#-ai-provider-setup)
  - [OpenAI](#openai)
  - [Google Gemini](#google-gemini)
  - [Ollama (Local AI)](#ollama-local-ai)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [Interactive Mode](#interactive-mode)
  - [Context Menu](#context-menu)
  - [Control Panel](#control-panel)
  - [Headless Mode](#headless-mode)
- [Vulnerability Categories](#-vulnerability-categories)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## 🛠 Installation

1. **Download the plugin**:
   ```bash
   # Save BinAIVulHunter.py to your IDA Pro plugins directory
   # Typically: C:\Program Files\IDA Pro X.X\plugins\
   ```

2. **Install base dependencies**:
   ```bash
   pip install psutil
   ```

3. **Install AI provider libraries** (choose one or more):
   ```bash
   # For OpenAI
   pip install openai
   
   # For Google Gemini
   pip install google-generativeai
   
   # For Ollama (local AI)
   pip install requests
   ```

4. **Restart IDA Pro** to load the plugin

## 🤖 AI Provider Setup

### OpenAI

1. **Get API Key**:
   - Visit [OpenAI API Keys](https://platform.openai.com/api-keys)
   - Create a new API key

2. **Set Environment Variable**:
   ```bash
   # Windows Command Prompt
   set OPENAI_API_KEY=sk-your-openai-key-here
   
   # PowerShell
   $env:OPENAI_API_KEY="sk-your-openai-key-here"
   
   # Linux/Mac
   export OPENAI_API_KEY="sk-your-openai-key-here"
   ```

3. **Restart IDA Pro**

### Google Gemini

1. **Get API Key**:
   - Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
   - Create a new API key

2. **Set Environment Variable**:
   ```bash
   # Windows Command Prompt
   set GEMINI_API_KEY=your-gemini-key-here
   
   # PowerShell
   $env:GEMINI_API_KEY="your-gemini-key-here"
   
   # Linux/Mac
   export GEMINI_API_KEY="your-gemini-key-here"
   ```

3. **Restart IDA Pro**

### Ollama (Local AI)

1. **Install Ollama**:
   - Visit [Ollama.ai](https://ollama.ai/) and download the installer
   - Or use package managers:
     ```bash
     # Linux
     curl -fsSL https://ollama.ai/install.sh | sh
     
     # macOS
     brew install ollama
     ```

2. **Start Ollama Service**:
   ```bash
   ollama serve
   ```

3. **Pull AI Models**:
   ```bash
   # For general code analysis
   ollama pull llama2
   
   # For coding tasks (recommended)
   ollama pull codellama
   
   # Other specialized models
   ollama pull mistral
   ollama pull deepseek-coder
   ```

4. **Optional Environment Variables**:
   ```bash
   # Custom Ollama server (if not localhost:11434)
   set OLLAMA_BASE_URL=http://your-server:11434
   
   # Set default model
   set OLLAMA_MODEL=codellama
   ```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | None | For OpenAI |
| `GEMINI_API_KEY` | Google Gemini API key | None | For Gemini |
| `OLLAMA_BASE_URL` | Ollama server URL | `http://localhost:11434` | No |
| `OLLAMA_MODEL` | Default Ollama model | `llama2` | No |
| `VULCHAT_PROVIDER` | AI provider to use | `openai` | No |
| `VULCHAT_MODEL` | Specific model name | Provider default | No |
| `OPENAI_BASE_URL` | Custom OpenAI endpoint | Official API | No |

### Provider Selection

Set your preferred AI provider:

```bash
# Use OpenAI (default)
set VULCHAT_PROVIDER=openai

# Use Google Gemini
set VULCHAT_PROVIDER=gemini

# Use Ollama (local)
set VULCHAT_PROVIDER=ollama
```

## 🎯 Usage

### Interactive Mode

1. **Open IDA Pro** with your binary file
2. **Navigate** to the decompiler view (F5)
3. **Access VulChat** via:
   - Menu: `Edit → VulChat`
   - Context menu: Right-click in decompiler view
   - Hotkeys (see below)

### Context Menu

Right-click in the decompiler view to access:

- **Find Possible Vulnerability** - Analyze current function for security issues
- **Explain** - Get AI explanation of function behavior
- **Rename Variables** - Get intelligent variable naming suggestions
- **Generate Safe Test Inputs** - Create test cases for the function
- **Scan All** - Batch vulnerability scan of entire binary
- **CWE Info** - Look up CWE vulnerability details
- **Control Panel** - Switch AI providers and configure settings

### Control Panel

Access via `Edit → VulChat → Control Panel` or `Ctrl+Alt+P`:

- **Switch AI Providers**: Change between OpenAI, Gemini, and Ollama
- **Model Selection**: Choose specific models for each provider
- **Status Information**: View current configuration and provider availability
- **Setup Guide**: Get detailed setup instructions

### Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Alt+V` | Find Vulnerabilities |
| `Ctrl+Alt+G` | Explain Function |
| `Ctrl+Alt+R` | Rename Variables |
| `Ctrl+Alt+X` | Generate Test Inputs |
| `Ctrl+Alt+S` | Scan All Functions |
| `Ctrl+Alt+W` | CWE Reference Lookup |
| `Ctrl+Alt+P` | Control Panel |
| `Ctrl+F5` | Decompile All Functions |

### Headless Mode

For automated analysis and CI/CD integration:

```bash
# Scan all functions for vulnerabilities
ida64.exe -A -S"BinAIVulHunter.py --scan-all --output results.json" binary.exe

# Decompile all functions with caching
ida64.exe -A -S"BinAIVulHunter.py --decompile-all --cache-dir ./cache" binary.exe

# Custom batch settings
ida64.exe -A -S"BinAIVulHunter.py --scan-all --batch-size 5 --function-pause 3 --batch-pause 15" binary.exe
```

#### Headless Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--scan-all` | Scan all functions for vulnerabilities | - |
| `--decompile-all` | Decompile all functions | - |
| `--batch-size` | Functions per batch | 3 |
| `--function-pause` | Pause between functions (seconds) | 5 |
| `--batch-pause` | Pause between batches (seconds) | 10 |
| `--output` | JSON output file for results | None |
| `--cache-dir` | Directory for decompilation cache | None |

## 🛡️ Vulnerability Categories

BinAIVulHunter analyzes code based on the CWE-699 Software Development taxonomy:

| Category | CWE ID | Examples |
|----------|--------|----------|
| **Memory Buffer Errors** | CWE-1218 | Buffer overflows, use-after-free |
| **Numeric Errors** | CWE-189 | Integer overflow, divide by zero |
| **Resource Management** | CWE-399 | Memory leaks, file handle leaks |
| **Data Validation** | CWE-1215 | Input validation, injection flaws |
| **Authentication** | CWE-1211 | Weak authentication, bypass |
| **Authorization** | CWE-1212 | Privilege escalation, access control |
| **Cryptographic Issues** | CWE-310 | Weak crypto, key management |
| **Information Leaks** | CWE-199 | Data exposure, side channels |
| **Error Handling** | CWE-389 | Uncaught exceptions, error states |
| **Initialization** | CWE-452 | Uninitialized variables, cleanup |

## 📚 Examples

### Example 1: Basic Vulnerability Scan

```python
# Navigate to a function in IDA Pro
# Press Ctrl+Alt+V or right-click → "Find Possible Vulnerability"

# Example output:
"""
POTENTIAL VULNERABILITIES:

1. Buffer overflow in strcpy operation
   CWE: CWE-120 | Severity: High
   Mitigation: Replace strcpy with strncpy and validate buffer sizes

2. Integer overflow in arithmetic operation
   CWE: CWE-190 | Severity: Medium  
   Mitigation: Add overflow checks before arithmetic operations
"""
```

### Example 2: Batch Scanning

```bash
# Command line batch scan
ida64.exe -A -S"BinAIVulHunter.py --scan-all --output vuln_report.json" malware.exe

# Results in vuln_report.json:
{
  "scan_results": {
    "total_functions": 245,
    "vulnerable_functions": 12,
    "functions": [
      {
        "name": "sub_401000",
        "address": "0x401000", 
        "vulnerabilities": [
          {
            "description": "Unsafe string function used",
            "cwe_id": "CWE-120",
            "severity": "High",
            "mitigation": "Use safe string functions"
          }
        ]
      }
    ]
  }
}
```

### Example 3: AI Provider Switching

```python
# Set environment variables
os.environ['VULCHAT_PROVIDER'] = 'ollama'
os.environ['OLLAMA_MODEL'] = 'codellama'

# Or use Control Panel in IDA Pro:
# Edit → VulChat → Control Panel → Provider Menu → Ollama
```

## 🔧 Troubleshooting

### Common Issues

1. **"Provider not available" error**:
   ```bash
   # Check environment variables
   echo %OPENAI_API_KEY%
   echo %GEMINI_API_KEY%
   
   # Verify API keys are valid
   # Restart IDA Pro after setting variables
   ```

2. **Ollama connection failed**:
   ```bash
   # Check if Ollama is running
   curl http://localhost:11434/api/tags
   
   # Start Ollama if needed
   ollama serve
   
   # Verify models are installed
   ollama list
   ```

3. **Memory issues during batch processing**:
   ```python
   # Reduce batch size in Control Panel or headless mode
   --batch-size 1 --function-pause 10
   ```

4. **API rate limits**:
   ```python
   # Increase pause times
   --function-pause 10 --batch-pause 30
   
   # Or switch to Ollama for unlimited local processing
   ```

### Debug Information

Check IDA Pro's output window for detailed logs:
- Provider initialization status
- API request/response information  
- Memory usage statistics
- Error messages and stack traces

## 🏆 Recommended AI Models

### For Security Analysis

| Provider | Model | Best For | Cost |
|----------|-------|----------|------|
| **OpenAI** | `gpt-4` | Comprehensive analysis | $$$ |
| **OpenAI** | `gpt-3.5-turbo` | Fast general analysis | $$ |
| **Gemini** | `gemini-pro` | Balanced performance | $$ |
| **Ollama** | `codellama` | Code-focused analysis | Free |
| **Ollama** | `deepseek-coder` | Vulnerability detection | Free |
| **Ollama** | `llama2` | General purpose | Free |

### Performance Comparison

| Provider | Speed | Accuracy | Privacy | Cost |
|----------|-------|----------|---------|------|
| OpenAI GPT-4 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐ |
| Gemini Pro | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| Ollama | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork the repository**
2. **Clone your fork**:
   ```bash
   git clone https://github.com/yourusername/BinAIVulHunter.git
   ```
3. **Install development dependencies**:
   ```bash
   pip install -e .[dev]
   ```
4. **Make your changes**
5. **Submit a pull request**

### Areas for Contribution

- Additional AI provider integrations
- Enhanced vulnerability detection patterns
- New CWE category support
- Performance optimizations
- Documentation improvements
- Test coverage expansion

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **IDA Pro**: https://www.hex-rays.com/products/ida/
- **OpenAI API**: https://platform.openai.com/
- **Google Gemini**: https://aistudio.google.com/
- **Ollama**: https://ollama.ai/
- **CWE Database**: https://cwe.mitre.org/

## 🙏 Acknowledgments

- Hex-Rays for the excellent IDA Pro platform
- OpenAI, Google, and Ollama teams for their AI technologies
- MITRE for the comprehensive CWE taxonomy
- The reverse engineering and cybersecurity community

---

**⚠️ Disclaimer**: This tool is for educational and legitimate security research purposes only. Always ensure you have proper authorization before analyzing any software. The AI-generated analysis should be manually verified and is not a substitute for expert human review.
