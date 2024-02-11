<h1 align="center">
CorsOne
</h1>

<h4 align="center">Fast Cors Misconfiguration Discovery Tool.</h4>

<p align="center">
<a href="https://github.com/omranisecurity/CorsOne/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/omranisecurity/CorsOne/releases"><img src="https://img.shields.io/github/release/CorsOne"></a>
<a href="https://github.com/omranisecurity/CorsOne/releases"><img src="https://img.shields.io/github/release/omranisecurity/CorsOne"></a>
<a href="https://twitter.com/omranisecurity"><img src="https://img.shields.io/twitter/follow/omranisecurity?logo=twitter"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a>
</p>

---

`CorsOne` is a tool designed to quickly and easily detect Cors misconfiguration, compensating for the shortcomings of other tools and providing automatic testing for all relevant cases.

# Features
- Accurate and fast diagnosis of Cors Misconfiguration vulnerability
- **STDIN** support enables easy integration with other tools or your own methodology

# Install
CorsOne requires Python v3 to install successfully.
```
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
python3 -m pip install -r requirements.txt or pip install -r requirements.txt
python3 corsone.py
```

# Usage
```python
python3 corsplus.py [-h] [-u URL] [-ch cookie/header] [-o OUTPUT]
```

This will display help for the tool. Here are all the switches it supports.

```yaml

Usage:
  python3 CorsOne.py [flags]

Flags:
INPUT:
  -u, --url                  URL to find Vulnerability

Config:
  -ch, --custom-headers      custom header to include in all http request in header:value format
  -p,  --proxy               specify a proxy to use during the scan

OUTPUT:
  -o, --output string        file to write output to

DEBUG:
  -s, --silent               show only Result in output
  -v, --version              show version of CorsOne
  -nc, --no-color            disable color in output
```

# Examples

* To check CORS misconfigurations of specific domain:

``python3 corsone.py -u https://example.com/``

* Check CORS misconfiguration for a list of URLs from a file:

``cat urls.txt | python3 corsone.py``

* To check CORS misconfiguration with specific headers:

``python3 corsone.py -u https://example.com/ -ch "Accept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate, br"``

* Check CORS misconfiguration with a specific proxy:

``python3 corsone.py -u https://example.com/ -p "http://ip:port/"``

* Save scan results to a file using -o:

``python3 corsone.py -u https://example.com/ -o output_filename.txt``


