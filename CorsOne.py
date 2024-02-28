#!/usr/bin/env python3

from urllib.parse import unquote
from urllib.parse import urlparse
import argparse
import requests
import fileinput
import validators
import sys
import os
from colorama import Fore

def banner():
    print("""
    █████████                                ███████                       
  ███░░░░░███                             ███░░░░░███                     
 ███     ░░░   ██████  ████████   █████  ███     ░░███ ████████    ██████ 
░███          ███░░███░░███░░███ ███░░  ░███      ░███░░███░░███  ███░░███
░███         ░███ ░███ ░███ ░░░ ░░█████ ░███      ░███ ░███ ░███ ░███████ 
░░███     ███░███ ░███ ░███      ░░░░███░░███     ███  ░███ ░███ ░███░░░  
 ░░█████████ ░░██████  █████     ██████  ░░░███████░   ████ █████░░██████ 
  ░░░░░░░░░   ░░░░░░  ░░░░░     ░░░░░░     ░░░░░░░    ░░░░ ░░░░░  ░░░░░░  
                                                                          
                    Github.com/omranisecurity/CorsOne
                     Developer: Mohammad Reza Omrani
                       LinkedIn/X: @omranisecurity
          """)

def Scan(url, custom_headers=None, proxy=None, output=None, silent=None, no_color=None):
    try:
        if not silent:
            banner()
            
        url = str(unquote(url, encoding='utf-8'))
        URLParsing = urlparse(url)
        origin = URLParsing.netloc
        
        if proxy:
            if proxy.startswith("http://") or proxy.startswith("https://"):
                proxies = {'http': proxy,'https': proxy}
                
            elif os.path.exists(proxy):
                with open(proxy, "r") as file:
                    proxy = file.readline().strip()
                    proxies = {'http': proxy,'https': proxy}
            else:
                print ("Enter the correct value of the proxy flag.")
                sys.exit(1)
        
        vulnerable_urls = []

        bypass_dict = {
            'Reflected Origin': 'attacker.com',
            'Trusted Subdomains': 'subdomain.' + origin,
            'Regexp bypass': origin + '.attacker.com',
            'Null Origin': 'Null',
            'Breaking TLS': 'http://' + origin,
            'Advance Regexp bypass 1': origin + ',.attacker.com',
            'Advance Regexp bypass 2': origin + '&.attacker.com',
            'Advance Regexp bypass 3': origin + "'.attacker.com",
            'Advance Regexp bypass 4': origin + '".attacker.com',
            'Advance Regexp bypass 5': origin + ';.attacker.com',
            'Advance Regexp bypass 6': origin + '!.attacker.com',
            'Advance Regexp bypass 7': origin + '$.attacker.com',
            'Advance Regexp bypass 8': origin + '^.attacker.com',
            'Advance Regexp bypass 9': origin + '*.attacker.com',
            'Advance Regexp bypass 10': origin + '(.attacker.com',
            'Advance Regexp bypass 11': origin + ').attacker.com',
            'Advance Regexp bypass 12': origin + '+.attacker.com',
            'Advance Regexp bypass 13': origin + '=.attacker.com',
            'Advance Regexp bypass 14': origin + '`.attacker.com',
            'Advance Regexp bypass 15': origin + '~.attacker.com',
            'Advance Regexp bypass 16': origin + '-.attacker.com',
            'Advance Regexp bypass 17': origin + '_.attacker.com',
            'Advance Regexp bypass 18': origin + '=.attacker.com',
            'Advance Regexp bypass 19': origin + '|.attacker.com',
            'Advance Regexp bypass 20': origin + '{.attacker.com',
            'Advance Regexp bypass 21': origin + '}.attacker.com',
            'Advance Regexp bypass 22': origin + '%.attacker.com',
        }
        
        for x, y in bypass_dict.items():    
            RequestHeader = {
                'user-agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
                'accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Origin': y
                }

            if custom_headers:
                for header_line in custom_headers.replace('\\n', '\n').splitlines():
                    header_name, header_value = map(str.strip, header_line.split(':', 1))
                    RequestHeader[header_name] = header_value

            if proxy:
                try:
                    response = requests.post(url, headers=RequestHeader, proxies=proxies)
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    print(f"Request error: {e}")
                    sys.exit(1)
            else:
                response = requests.post(url, headers=RequestHeader)

            ACAC = bool(response.headers.get('Access-Control-Allow-Credentials'))
            ACAO = str(response.headers.get('Access-Control-Allow-Origin'))

            if ACAC and ACAO == y:
                status = '[Vulnerable]'
                vulnerable_urls.append(f"{url} {status} {x}: {y}") 
            else:
                status = '[Not Vulnerable]'

            if no_color:
                print(f"{Fore.GREEN if status == '[Vulnerable]' else Fore.RED}{status} {x}: {Fore.RESET}{y}")
            else:
                print(f"{status} {x}: {y}")

            if output and len(vulnerable_urls) > 0:
                file = open(output, "w")
                for item in vulnerable_urls:
                    file.write(item+"\n")
                file.close()

    except KeyboardInterrupt:
        print('You have pressed the ctrl + c button.')
        sys.exit(1)

def validation(url):
    return validators.url(url)

def version():
    return "v0.9.0"

def main():
    parser = argparse.ArgumentParser(prog='CorsOne', description='Check CORS vulnerability', epilog='Verion: 0.9.0')
    parser.add_argument('-u', '--url', type=str, help="URL to find Vulnerability")
    parser.add_argument('-ch', '--custom-headers', type=str, help='custom header to include in all http request in header:value format. -ch "header1: value1\nheader2: value2"')
    parser.add_argument('-p', '--proxy', type=str, help='specify a proxy to use during the scan. -p "http://ip:port/"')
    parser.add_argument('-s', '--silent', action='store_true', help='show only Result in output')
    parser.add_argument('-v', '--version', action='store_true', help='show version of CorsOne')
    parser.add_argument('-nc', '--no-color', action='store_false', help='disable color in output')
    parser.add_argument('-o', '--output', help="file to write output to")
    args = parser.parse_args()

    url = args.url
    custom_headers = args.custom_headers
    proxy = args.proxy
    silent = args.silent
    version_info = args.version
    no_color = args.no_color
    output = args.output
    stdin = not sys.stdin.isatty()
    
    if url and not stdin:
        if validation(url):
            Scan(url, custom_headers, proxy, output, silent, no_color)
        elif not validation(url):
                print("The URL isn't Valid!")
                sys.exit(1)
            
    elif stdin and not url:
        for stdin_data in sys.stdin:
            stdin_data = stdin_data.strip()
            if validation(stdin_data):
                Scan(stdin_data, custom_headers, proxy, output, silent, no_color)
            elif not validation(stdin_data):
                print("The URL isn't Valid!")
                sys.exit(1)

    elif version_info:
        print(version())

    elif stdin and url:
        print("Error: You cannot provide both stdin input and use the -u flag simultaneously.")
        sys.exit(1)

    else:
        print("no input list provided. please provide either a URL or input via stdin.")

if __name__ == "__main__":
    main()
