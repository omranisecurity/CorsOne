<h1 align="center">
CorsOne
</h1>

<h4 align="center">Fast CORS Misconfiguration Discovery Tool.</h4>

<p align="center">
<a href="https://github.com/omranisecurity/CorsOne/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/omranisecurity/CorsOne/releases"><img src="https://img.shields.io/badge/release-v0.9.5-blue"></a>
<a href="https://twitter.com/omranisecurity"><img src="https://img.shields.io/twitter/follow/omranisecurity?logo=twitter"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a>
</p>

---

[![CorsOne ](https://asciinema.org/a/OKANAbkXi3PGRGTAOEb5dxUA5.svg)](https://asciinema.org/a/OKANAbkXi3PGRGTAOEb5dxUA5?autoplay=1)
`CorsOne` is a tool designed to quickly and easily detect CORS misconfiguration, compensating for the shortcomings of other tools and providing automatic testing for all relevant cases.

# Features
- Accurate and fast diagnosis of CORS Misconfiguration vulnerability
- **STDIN** support enables easy integration with other tools or your own methodology

# Install
CorsOne requires Python v3 to install successfully.
```
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
python3 -m pip install -r requirements.txt
```

# Usage
```python
python3 CorsOne [-h] [-u URL] [-l LIST] [-sof] [-ch CUSTOM_HEADERS] [-rl RATE_LIMIT] [-m {GET,POST}] [-p PROXY] [-s] [-v] [-nc] [-o OUTPUT]
```

This will display help for the tool. Here are all the switches it supports.

```yaml

Usage:
  python3 CorsOne.py [flags]

Flags:
INPUT:
  -u, --url                  input target url to probe
  -l, --list                 input file list of URLs

Config:
  -sof,  --stop-on-first     stop testing after finding the first vulnerability
  -ch, --custom-headers      custom header to include in all http request in header:value format. -ch "header1: value1\nheader2: value2"
  -rl,  --rate-limit         maximum requests to send per second
  -m, --method               HTTP method for the request
  -p,  --proxy               SOCKS Proxy to use (eg -p "socks5://127.0.0.1:6060")

OUTPUT:
  -o, --output string        file to write output to

DEBUG:
  -s, --silent               show only result in output
  -v, --version              show version of CorsOne
  -nc, --no-color            disable color in output
```

# Examples

* To check CORS misconfigurations for a specific domain:

``python3 CorsOne.py -u https://example.com/``

* To check CORS misconfigurations for a list of domains:

``cat urls.txt | python3 CorsOne.py``

or

``python3 CorsOne.py -l list.txt``

* Stop after finding the first CORS vulnerability:

``python3 CorsOne.py -u https://example.com/ -ch "Cookie: name=value;\nAccept-Encoding: gzip, deflate, br"``

* Check CORS misconfigurations with custom headers:

``python3 CorsOne.py -u https://example.com/ -ch "Cookie: name=value;\nAccept-Encoding: gzip, deflate, br"``

* Check CORS misconfigurations with rate limit:

``python3 CorsOne.py -u https://example.com/ -rl 5``

* Check CORS misconfigurations with a custom HTTP method (default GET):

``python3 CorsOne.py -u https://example.com/ -m POST``

* Check CORS misconfigurations using a proxy:

``python3 CorsOne.py -u https://example.com/ -p "socks5://ip:port/"``

* Save scan results to a file using -o:

``python3 CorsOne.py -u https://example.com/ -o output_filename.txt``

---

# Acknowledgment
- Thanks to <a href="https://book.hacktricks.xyz/pentesting-web/cors-bypass">hacktricks.xyz</a> for sharing the resources.
