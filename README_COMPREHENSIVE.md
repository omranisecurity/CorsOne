# 🛡️ CorsOne - CORS Misconfiguration Detection Tool

<div align="center">

![CorsOne Banner](https://img.shields.io/badge/Security%20Tool-CORS%20Testing-red?style=flat-square)
![Python Version](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Latest Release](https://img.shields.io/badge/Release-v0.9.9-brightblue?style=flat-square)

**Fast, Accurate, and Comprehensive CORS Misconfiguration Detection**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Usage Guide](#-usage-guide) • [Examples](#-examples) • [Tutorial](#-tutorial)

</div>

---

## 📋 Table of Contents

1. [What is CorsOne?](#what-is-corsone)
2. [Features](#-features)
3. [Installation](#-installation)
4. [Quick Start](#-quick-start)
5. [Usage Guide](#-usage-guide)
6. [CLI Options](#-cli-options)
7. [Examples](#-examples)
8. [Tutorial](#-tutorial)
9. [Output Explanation](#-output-explanation)
10. [Troubleshooting](#-troubleshooting)
11. [Contributing](#-contributing)

---

## What is CorsOne?

**CorsOne** is a specialized security testing tool designed to detect and identify **Cross-Origin Resource Sharing (CORS)** misconfigurations in web applications. It automates the process of testing for CORS vulnerabilities that could allow attackers to:

- Access sensitive data from authenticated users
- Perform unauthorized actions on behalf of users
- Bypass Same-Origin Policy (SOP) restrictions
- Steal credentials and session tokens

### Why CorsOne?

Unlike generic security scanners, CorsOne:
- ✅ **Tests 40+ CORS bypass techniques** automatically
- ✅ **Provides accurate results** with low false positives
- ✅ **Fast scanning** - can test multiple URLs quickly
- ✅ **Easy integration** - supports STDIN and file input
- ✅ **Flexible customization** - supports custom headers, proxies, and methods
- ✅ **Color-coded output** - easy to identify vulnerabilities
- ✅ **Docker support** - no dependency installation needed

---

## ✨ Features

### Core Features
- **Automatic CORS Misconfiguration Detection** - Tests multiple bypass techniques
- **Multiple Input Methods**
  - Single URL with `-u` flag
  - Multiple URLs from file with `-l` flag
  - STDIN piping for easy integration
- **Customizable Origin Testing** - Test with custom domains instead of default "attacker.com"
- **Flexible HTTP Methods** - Support for GET, POST, PUT, DELETE, etc.
- **Rate Limiting** - Control request frequency to avoid detection
- **Proxy Support** - Route requests through HTTP/HTTPS proxies
- **Stop-on-First Detection** - Exit immediately after finding first vulnerability
- **File Output** - Save results to file for reporting

### Technical Features
- **No False Positives** - Checks for both ACAO header and credentials flag
- **URL Validation** - Automatically validates and formats URLs
- **Color-Coded Output** - Green for vulnerable, red for not vulnerable
- **Error Handling** - Graceful handling of network errors and timeouts
- **Keyboard Interrupt Support** - Safely cancel operations with Ctrl+C

### Bypass Techniques Tested
1. **Reflected Origin** - Direct origin reflection
2. **Breaking TLS** - HTTP/HTTPS protocol mixing
3. **Trusted Subdomains** - Subdomain bypasses
4. **Null Origin** - Testing null origin header
5. **Domain Ending Bypasses** - Various character injections
6. **Localhost Edge Cases** - Localhost regex bypasses
7. **Domain Separation Bypasses** - 20+ variants with special characters
8. **Advanced Regexp Bypasses** - Regex metacharacter injections

---

## 🚀 Installation

### Option 1: Docker (Recommended - No Setup Required)

The easiest way to run CorsOne without installing dependencies:

```bash
# Pull the official Docker image
docker pull omranisecurity/corsone:latest

# Run a quick scan
docker run --rm omranisecurity/corsone:latest -u https://example.com/
```

### Option 2: Quick Start with Python

**Prerequisites**
- Python 3.7 or higher
- pip (Python package manager)
- git (for cloning the repository)

**Installation Steps**

```bash
# 1. Clone the Repository
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne

# 2. Create Virtual Environment (Recommended)
python3 -m venv corsone-env
source corsone-env/bin/activate    # On Windows: corsone-env\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Verify Installation
python3 CorsOne_professional.py --help

# 5. Deactivate When Done
deactivate
```

### Option 3: Install from Source Without Virtual Environment

```bash
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
pip install -r requirements.txt
python3 CorsOne.py -u https://example.com/
```

#### ⚙️ Dependency Management


- **[requirements.txt](requirements.txt)** - Core dependencies

```bash
# Install development dependencies
pip install -r requirements.txt
```

---

## ⚡ Quick Start

### Simplest Usage - Scan a Single URL

```bash
# Using Docker
docker run --rm omranisecurity/corsone:latest -u https://example.com/

# Or with Python (after installation)
python3 CorsOne.py -u https://example.com/
```

### Scan Multiple URLs from a File

```bash
# Create a file with URLs (one per line)
echo "https://example1.com/" > targets.txt
echo "https://example2.com/" >> targets.txt

# Scan them
python3 CorsOne.py -l targets.txt
```

### Pipe URLs from Another Tool

```bash
# Using with other tools
echo "https://example.com/" | python3 CorsOne.py

# Using with cat command
cat url_list.txt | python3 CorsOne.py

# Combine with other security tools
tool-name | python3 CorsOne.py
```

### Quick Vulnerability Check

```bash
# Stop after finding the first vulnerability
python3 CorsOne.py -u https://example.com/ -sof
```

---

## 📖 Usage Guide

### Basic Command Structure

```bash
python3 CorsOne.py [OPTIONS]
```

### Input Options

**Single URL:**
```bash
python3 CorsOne.py -u https://example.com/
python3 CorsOne.py --url https://example.com/api/data
```

**Multiple URLs from File:**
```bash
python3 CorsOne.py -l urls.txt
python3 CorsOne.py --list targets.txt
```

**From STDIN (Piped Input):**
```bash
cat urls.txt | python3 CorsOne.py
echo "https://example.com/" | python3 CorsOne.py
```

### Output Options

**Save Results to File:**
```bash
python3 CorsOne.py -u https://example.com/ -o results.txt
python3 CorsOne.py -u https://example.com/ --output findings.txt
```

**Specify Output Format (TXT or JSON):**
```bash
# Specify format explicitly
python3 CorsOne.py -u https://example.com/ -o results -f json
python3 CorsOne.py -u https://example.com/ -o results --format txt

# Or use file extension (takes priority)
python3 CorsOne.py -u https://example.com/ -o results.json  # → results.json
python3 CorsOne.py -u https://example.com/ -o results.txt   # → results.txt
```

**Save Debug Logs:**
```bash
# Only creates log file if specified (no extra files otherwise)
python3 CorsOne.py -u https://example.com/ --log scan.log
python3 CorsOne.py -u https://example.com/ --log debug_info.log -v
```

**Specify Output Format (TXT or JSON):**
```bash
# Specify format explicitly
python3 CorsOne.py -u https://example.com/ -o results -f json
python3 CorsOne.py -u https://example.com/ -o results --format txt

# Or use file extension (takes priority)
python3 CorsOne.py -u https://example.com/ -o results.json  # → results.json
python3 CorsOne.py -u https://example.com/ -o results.txt   # → results.txt
```

**Save Debug Logs (Only When Specified):**
```bash
# Only creates log file if specified - no extra files otherwise
python3 CorsOne.py -u https://example.com/ --log scan.log
python3 CorsOne.py -u https://example.com/ --log debug_info.log -v

# Combined with results output
python3 CorsOne.py -u https://example.com/ -o results.txt --log debug.log
```

**Disable Color Output:**
```bash
python3 CorsOne.py -u https://example.com/ -nc
python3 CorsOne.py -u https://example.com/ --no-color
```

### Customization Options

**Custom Domain for Testing:**
```bash
# Instead of "attacker.com", use your domain
python3 CorsOne.py -u https://example.com/ -d attacker.com
python3 CorsOne.py -u https://example.com/ --domain your-domain.com
```

**Custom HTTP Method:**
```bash
# Default is GET, change to POST, PUT, DELETE, etc.
python3 CorsOne.py -u https://example.com/ -m POST
python3 CorsOne.py -u https://example.com/ --method PUT
```

**Rate Limiting:**
```bash
# Add delay between requests (in seconds)
python3 CorsOne.py -l urls.txt -r 2
python3 CorsOne.py -l urls.txt --rate-limit 1.5
```

**Proxy Support:**
```bash
# Route requests through a proxy
python3 CorsOne.py -u https://example.com/ -p http://127.0.0.1:8080
python3 CorsOne.py -u https://example.com/ --proxy https://proxy.company.com:3128
```

**Stop on First Vulnerability:**
```bash
# Exit after finding the first vulnerability
python3 CorsOne.py -u https://example.com/ -sof
python3 CorsOne.py -l urls.txt --stop-on-first
```

**Custom Headers:**
```bash
# Add custom headers to requests
python3 CorsOne.py -u https://example.com/ -H "Cookie: session=321cba"
python3 CorsOne.py -u https://example.com/ --headers "Cookie: session=abc123"
```

---

## 🎯 CLI Options

| Option | Short | Type | Description | Example |
|--------|-------|------|-------------|---------|
| URL | `-u` | string | Target URL to scan | `-u https://example.com/` |
| List | `-l` | file | File containing URLs | `-l targets.txt` |
| Output | `-o` | file | Save results to file | `-o results.txt` |
| Format | `-f` | choice | Output format (txt/json) | `-f json` |
| Log | `--log` | file | Save debug logs to file | `--log scan.log` |
| No Color | `-nc` | flag | Disable colored output | `-nc` |
| Domain | `-d` | string | Custom domain for testing | `-d attacker.com` |
| Method | `-m` | string | HTTP method to use | `-m POST` |
| Workers | `-w` | int | Concurrent workers (default: 5) | `-w 10` |
| Rate Limit | `-rl` | float | Delay between requests (sec) | `-rl 2` |
| Timeout | `-t` | int | Request timeout (seconds) | `-t 15` |
| Retries | `-r` | int | Number of retries | `-r 3` |
| Proxy | `-p` | string | HTTP/HTTPS proxy URL | `-p http://proxy:8080` |
| Stop on First | `-sof` | flag | Exit after first vulnerability | `-sof` |
| Verbose | `-v` | flag | Verbose logging | `-v` |
| Silent | `-s` | flag | No banner output | `-s` |
| Help | `-h` | flag | Show help message | `-h` |
| Version | `--version` | flag | Show version information | `--version` |

---

## 🔧 Examples

### Example 1: Basic Single URL Scan
```bash
python3 CorsOne.py -u https://api.example.com/

# Output:
# [Vulnerable] Reflected Origin: https://attacker.com]
# [Vulnerable] Breaking TLS: http://api.example.com
# [Not Vulnerable] Null Origin: null
# ...
```

### Example 2: Batch Scanning with File
```bash
# Create targets file
cat > targets.txt << EOF
https://api1.example.com/
https://api2.example.com/
https://api3.example.com/
EOF

# Scan all targets
python3 CorsOne.py -l targets.txt -o results.txt

# Output saved to results.txt
```

### Example 3: JSON Output for Automation

```bash
# Save results as JSON for parsing
python3 CorsOne.py -u https://example.com/ -o results.json

# Or specify format explicitly
python3 CorsOne.py -u https://example.com/ -o results -f json

# Use with jq to filter vulnerable endpoints
jq '.[] | select(.is_vulnerable==true)' results.json
```

### Example 4: Debug Logging

```bash
# Save debug logs to file (only creates if specified)
python3 CorsOne.py -u https://example.com/ --log scan.log

# Combine with verbose output
python3 CorsOne.py -u https://example.com/ -v --log debug.log

# Results + Logs together
python3 CorsOne.py -u https://example.com/ -o findings.txt --log activity.log
```

### Example 5: Quick Vulnerability Check
```bash
# Stop after finding first vulnerability
python3 CorsOne.py -u https://example.com/ -sof -d evil.com
```

### Example 6: POST Request Scanning
```bash
# Test CORS on POST endpoints
python3 CorsOne.py -u https://api.example.com/api/data -m POST
```

### Example 7: Using Proxy for Testing
```bash
# Route through Burp Suite for inspection
python3 CorsOne.py -u https://example.com/ -p http://127.0.0.1:8080 -nc
```

### Example 8: Integration with Other Tools
```bash
# Get URLs from subfinder and scan them
subfinder -d example.com | python3 CorsOne.py -r 1

# Get URLs from other tools
cat urls.txt | python3 CorsOne.py -o cors_findings.txt

```

### Example 9: Custom Headers
```bash
# Test endpoints requiring authentication
python3 CorsOne.py -u https://api.example.com/ \
  -H "Cookie: sessionid=abc123"
```

### Example 10: Using Docker with Options
```bash
# Docker with multiple options
docker run --rm omranisecurity/corsone:latest \
  -u https://example.com/ \
  -m POST \
  -d malicious.com \
  -nc

# Scan from file with Docker (mount volume)
docker run --rm -v $(pwd):/app omranisecurity/corsone:latest \
  -l /app/targets.txt \
  -o /app/results.txt
```

---

## 📚 Tutorial

### Tutorial 1: First Time Setup and Basic Scan

**Step 1: Install Dependencies**
```bash
# Clone the repository
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne

# Create virtual environment
python3 -m venv corsone-env
source corsone-env/bin/activate

# Install requirements
pip install -r requirements.txt
```

**Step 2: Run Your First Scan**
```bash
# Test with a public website
python3 CorsOne.py -u https://example.com/

# Watch the output for [Vulnerable] or [Not Vulnerable] messages
```

**Step 3: Understand the Output**
```
[Vulnerable] Reflected Origin: https://attacker.com]  ← CORS vulnerability found!
[Not Vulnerable] Breaking TLS: http://example.com      ← No vulnerability here
[Not Vulnerable] Null Origin: null                      ← This bypass didn't work
```

---

### Tutorial 2: Output Formats and Results Management

**Scenario:** You want to save results in specific format for automation or reporting

**Step 1: JSON Output for Automation**
```bash
# Save as JSON for programmatic parsing
python3 CorsOne.py -u https://example.com/ -o scan_results.json

# Filter vulnerable endpoints with jq
jq '.[] | select(.is_vulnerable==true) | .bypass_name' scan_results.json

# Get count of vulnerabilities
jq '[.[] | select(.is_vulnerable==true)] | length' scan_results.json
```

**Step 2: TXT Output for Reporting**
```bash
# Save as text for human-readable reports
python3 CorsOne.py -u https://example.com/ -o scan_results.txt

# View results
cat scan_results.txt

# Filter vulnerable lines
grep "VULNERABLE" scan_results.txt
```

**Step 3: Enable Debug Logging**
```bash
# Save detailed logs for troubleshooting
python3 CorsOne.py -u https://example.com/ --log scan_debug.log

# View logs
cat scan_debug.log

# Combine with verbose output
python3 CorsOne.py -u https://example.com/ -v --log detailed.log -o results.txt
```

---

### Tutorial 2: Scanning Multiple URLs and Saving Results

**Step 1: Create a Target File**
```bash
cat > my_targets.txt << 'EOF'
https://api.company1.com/
https://api.company2.com/
https://app.company3.com/api
EOF
```

**Step 2: Run Batch Scan**
```bash
python3 CorsOne.py -l my_targets.txt -o cors_report.txt
```

**Step 3: Review Results**
```bash
# View all results
cat cors_report.txt

# View only vulnerable endpoints
grep "Vulnerable" cors_report.txt

# Count vulnerabilities
grep "Vulnerable" cors_report.txt | wc -l
```

---

### Tutorial 3: Advanced Scanning with Custom Domains

**Scenario:** You want to test CORS with your own domain instead of "attacker.com"

**Step 1: Prepare**
```bash
# Create target list
echo "https://api.target.com/" > targets.txt

# Make sure you own or control the domain you'll use
# For this example, let's use "evil.domain.com"
```

**Step 2: Run Scan with Custom Domain**
```bash
python3 CorsOne.py -l targets.txt -d evil.domain.com -o results.txt
```

**Step 3: Analyze Results**
```bash
# Results will show bypasses like:
# [Vulnerable] Reflected Origin: https://evil.domain.com]
# This means the server reflects back your custom domain
```

---

### Tutorial 4: Integration with Security Workflows

**Scenario:** Integrate CorsOne into your security testing pipeline

**Step 1: Recon Phase - Gather URLs**
```bash
# Using amass (example tool)
amass enum -d example.com -o urls.txt
```

**Step 2: Filter to API endpoints**
```bash
grep -E "(api|ajax|rest)" urls.txt > api_urls.txt
```

**Step 3: Scan for CORS Issues**
```bash
python3 CorsOne.py -l api_urls.txt -r 1 -o cors_findings.txt
```

**Step 4: Report Vulnerable Endpoints**
```bash
# Extract only vulnerable endpoints
grep "Vulnerable" cors_findings.txt > critical_issues.txt

# Count them
wc -l critical_issues.txt
```

---

### Tutorial 5: Testing Authenticated Endpoints

**Scenario:** Your target requires authentication - use custom headers

**Step 1: Obtain Valid Session**
```bash
# Get your session token/cookie from the application
# Store it in a variable or file
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
COOKIE="sessionid=abc123def456"
```

**Step 2: Scan with Authentication**
```bash
python3 CorsOne.py -u https://api.example.com/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $COOKIE"
```

**Step 3: Analyze Results**
```bash
# The scan will use your authenticated session
# This helps find CORS issues in protected endpoints
```

---

### Tutorial 6: Proxy-Based Testing (Burp Suite Integration)

**Scenario:** You want to intercept and inspect requests in Burp Suite

**Step 1: Start Burp Suite**
- Launch Burp Suite
- Go to Settings → Network → Proxy and note the port (usually 8080)

**Step 2: Run CorsOne Through Proxy**
```bash
python3 CorsOne.py -u https://example.com/ \
  -p http://127.0.0.1:8080 \
  -nc  # Disable color for clarity in Burp
```

**Step 3: Inspect in Burp Suite**
- All requests will appear in Burp's Proxy → HTTP History
- You can see the Origin headers being tested
- Inspect responses for CORS headers

---

### Tutorial 7: Rate-Limited Scanning (Avoid Detection)

**Scenario:** Target has rate limiting or IDS detection

**Step 1: Identify Optimal Rate**
```bash
# Start slow - 1 request per second
python3 CorsOne.py -u https://example.com/ -r 1
```

**Step 2: If Getting Blocked, Increase Delay**
```bash
# Wait 2 seconds between each request
python3 CorsOne.py -l targets.txt -r 2 -o results.txt
```

**Step 3: Monitor for Rate Limit Errors**
```bash
# Check if you're getting rate limit errors
python3 CorsOne.py -l targets.txt -r 3 | tee scan.log

# Analyze log for errors
grep -i "error\|429\|rate" scan.log
```

---

### Tutorial 8: CORS Testing on Different HTTP Methods

**Scenario:** API supports multiple HTTP methods (GET, POST, PUT, DELETE)

**Step 1: Test GET Requests** (default)
```bash
python3 CorsOne.py -u https://api.example.com/users -m GET
```

**Step 2: Test POST Requests**
```bash
python3 CorsOne.py -u https://api.example.com/users -m POST
```

**Step 3: Test Other Methods**
```bash
# PUT method
python3 CorsOne.py -u https://api.example.com/users/123 -m PUT

# DELETE method
python3 CorsOne.py -u https://api.example.com/users/123 -m DELETE

# OPTIONS method (often reveals CORS configuration)
python3 CorsOne.py -u https://api.example.com/users -m OPTIONS
```
---

## 📊 Output Explanation

### Understanding the Results

```
[Vulnerable] Reflected Origin: https://attacker.com]
[Not Vulnerable] Breaking TLS: http://example.com
[Vulnerable] Trusted Subdomains: https://subdomain.example.com
```

**[Vulnerable]** (Green in terminal)
- The server responded with `Access-Control-Allow-Origin: [origin]` AND `Access-Control-Allow-Credentials: true`
- This is a real CORS vulnerability
- An attacker could exploit this

**[Not Vulnerable]** (Red in terminal)
- The server did NOT respond with both required headers
- Either the origin wasn't allowed OR credentials flag wasn't set
- This bypass technique didn't work

### Sample Output File

```
https://api.example.com/ [Vulnerable] Reflected Origin: https://attacker.com]
https://api.example.com/ [Vulnerable] Breaking TLS: http://api.example.com
https://api.example.com/ [Not Vulnerable] Null Origin: null
https://api.example.com/ [Not Vulnerable] Trusted Subdomains: https://subdomain.example.com
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Report Issues
Found a bug? Have a feature request?
- Visit: https://github.com/omranisecurity/CorsOne/issues
- Provide detailed description of the problem
- Include example commands and output

### Contribute Code
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Developer

**CorsOne** is developed and maintained by:

- **Mohammad Reza Omrani**
  - Twitter/X: [@omranisecurity](https://twitter.com/omranisecurity)
  - LinkedIn: [Mohammad Reza Omrani](https://linkedin.com/in/omranisecurity)
  - GitHub: [omranisecurity](https://github.com/omranisecurity)

---

## ⭐ Support

If you find CorsOne helpful:
- ⭐ Star the repository on GitHub
- 🐛 Report bugs and suggest features
- 📢 Share with your security community
- 💬 Provide feedback and improvements

---

## 📚 Additional Resources

### CORS Security Documentation
- [OWASP CORS Documentation](https://owasp.org/www-community/attacks/cors)
- [MDN CORS Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [What is CORS (cross-origin resource sharing)?](https://portswigger.net/web-security/cors)

### Learning Resources
- [PortSwigger - Cross-origin resource sharing (CORS)](portswigger.net/web-security/all-labs#cross-origin-resource-sharing-cors)

---

**Happy CORS Testing! 🛡️**

For questions or support, visit the GitHub repository or contact the developer.
