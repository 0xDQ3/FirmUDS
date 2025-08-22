# UDS Security Access Code Location and Vulnerability Scanner

## Project Introduction

This tool is an automated reverse engineering script based on Ghidra, specifically designed to locate UDS diagnostic protocol 27 sub-service (Security Access) related code in ECU firmware and perform security vulnerability scanning. The tool can automatically identify Seed2Key algorithms, random number generators, key comparison components, and detect various security vulnerabilities.

## Main Features

- **Automatic Code Location**: Identify UDS 27 sub-service related functions based on byte manipulation patterns
- **Intelligent Analysis**: Use large language models to analyze decompiled code logic
- **Vulnerability Scanning**: Detect hardcoded keys, algorithmic flaws, authentication logic vulnerabilities, etc.
- **State Recovery**: Support interrupt recovery to avoid repeated analysis
- **Detailed Logging**: Provide complete analysis process and result records

## Build Environment

### 1. Install Ghidrathon

First, install the Ghidrathon plugin to support Python scripts:

1. Download Ghidrathon plugin: https://github.com/mandiant/Ghidrathon
2. Install the plugin to Ghidra's Extensions directory
3. Restart Ghidra and confirm Python environment is available

### 2. Install Python Dependencies

```bash
pip install openai langchain-community
```

## Running Steps

### 1. Configure LLM Parameters

Configure your API keys in the `LLM_CONFIG` section at the top of `FirmUDS.py`:

```python
LLM_CONFIG = {
    "qwen": {
        "api_key": "your_qwen_api_key",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-max-2025-01-25"
    },
    "moonshot": {
        "api_key": "your_moonshot_api_key",
        "base_url": "https://api.moonshot.cn/v1", 
        "model": "moonshot-v1-32k"
    }
}
```

### 2. Prepare Firmware File

1. Start Ghidra
2. Import target ECU firmware file
3. **Important**: Perform forced full firmware analysis
   - For Tricore/PPC architectures, some normal functions may be ignored
   - Ensure analysis covers all code segments
   - Set appropriate analysis options to include all functions

### 3. Run Script

1. Open Script Manager in Ghidra
2. Select `FirmUDS.py` script
3. Click Run
4. Enter suspected random number generator function names as prompted

## Analysis Stage Description

### Stage 1: UDS27 Feature Function Identification
- **Function**: Scan all functions to identify those containing `<< 0x18` and `<< 0x10` byte manipulation patterns
- **Output**: `logs/log_1.txt` - List of matching functions
- **Filter Criteria**: Must contain both shift operations and byte manipulation features

### Stage 2: Random Number Generator Association Analysis
- **Function**: Analyze call relationships between random number generators and UDS27 functions
- **Output**: `logs/log_2.txt` - Candidate function list
- **Input**: User-provided suspected random number generator function names

### Stage 3: LLM Intelligent Judgment
- **Function**: Use large language models to determine if candidate functions truly have UDS27 features
- **Output**: `logs/log_3.txt` - Final hit function list
- **Filter Criteria**: Code lines 5-120, judged as UDS27-related by LLM

### Stage 4: Function Completeness Analysis
- **Function**: Analyze whether the four core components of UDS27 service are complete
- **Output**: `logs/log_4.txt` and `logs/uds27_overview.json`
- **Components**: Seed generation, Seed splitting, Seed2Key algorithm, Key value comparison

### Stage 5: Vulnerability Scanning
- **Function**: Scan security vulnerabilities in identified UDS27 code
- **Output**: `logs/log_5.txt` and `logs/vulnerability_scan.json`
- **Vulnerability Types**: Information leakage, algorithmic flaws, authentication logic flaws

## Log Output Description

### Main Log Files
- `logs/log.txt` - Complete execution log
- `logs/log_1.txt` - Stage 1 results
- `logs/log_2.txt` - Stage 2 results
- `logs/log_3.txt` - Stage 3 results
- `logs/log_4.txt` - Stage 4 results
- `logs/log_5.txt` - Stage 5 results

### Result Files
- `logs/uds27_overview.json` - UDS27 function completeness analysis results
- `logs/vulnerability_scan.json` - Detailed vulnerability scanning results
- `logs/llm_error_state.json` - LLM error recovery state (if needed)
- `logs/code_items_functions.json` - List of functions to be analyzed

## Main Detected Vulnerability Types

### 1. Information Leakage Vulnerabilities
- **Hardcoded Keys**: Detect pre-shared keys directly stored in firmware
- **Sensitive Data Exposure**: Identify potentially leaked seed values or key data

### 2. Algorithmic Flaws
- **Weak Seed2Key Algorithm**: Detect simple algorithms lacking non-linear operations
- **Short Key Length**: Identify security risks from insufficient key length

### 3. Authentication Logic Flaws
- **Insufficient Randomness**: Detect entropy source issues in random number generators
- **Replay Attack Vulnerabilities**: Identify design flaws lacking replay protection
