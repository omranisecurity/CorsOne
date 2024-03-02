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
from time import sleep

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

def Scan(url, custom_headers=None, proxy=None, output=None, silent=None, no_color=None, rate_limit=None):
    try:
        url = str(unquote(url, encoding='utf-8'))
        URLParsing = urlparse(url)
        origin = URLParsing.netloc
        
        Endpoints = []

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
        
        RequestHeader = {
                'user-agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
                'accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
                }

        if custom_headers:
                for header_line in custom_headers.replace('\\n', '\n').splitlines():
                    header_name, header_value = map(str.strip, header_line.split(':', 1))
                    RequestHeader[header_name] = header_value
        if proxy:
                proxies = proxy_check(proxy)
                
        for x, y in bypass_dict.items():
            RequestHeader['origin'] = y
            if proxy:
                try:
                    response = requests.post(url, headers=RequestHeader, proxies=proxies)
                except requests.exceptions.RequestException as e:
                    print(f"Request error: {e}")
                    sys.exit(1)
            else:
                response = requests.get(url, headers=RequestHeader)

            ACAC = bool(response.headers.get('Access-Control-Allow-Credentials'))
            ACAO = str(response.headers.get('Access-Control-Allow-Origin'))

            if ACAC and ACAO == y:
                status = '[Vulnerable]'
                Endpoints.append(f"{url} {status} {x}: {y}")
            else:
                status = '[Not Vulnerable]'
                Endpoints.append(f"{url} {status} {x}: {y}")

            if no_color:
                print(f"{Fore.GREEN if status == '[Vulnerable]' else Fore.RED}{status} {x}: {Fore.RESET}{y}")
            else:
                print(f"{status} {x}: {y}")

            if rate_limit:
                sleep(rate_limit)

        if output:
            file = open(output, "a")
            for item in Endpoints:
                file.write(item+"\n")
            file.close()

    except KeyboardInterrupt:
        print('You have pressed the ctrl + c button.')
        sys.exit(1)

def proxy_check(proxy):
    working_proxies = []
    if proxy.startswith("http://") or proxy.startswith("https://") or proxy.startswith("socks4://") or proxy.startswith("socks5://"):
        proxies = {'http': proxy,'https': proxy}
        try:
            response = requests.get("https://api.github.com/", proxies=proxies)
            if response and response.ok:
                working_proxies.append(proxies)
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            sys.exit(1)

    elif os.path.exists(proxy):
        with open(proxy, "r") as file:
            proxy_list = file.read().splitlines()
            for proxy in proxy_list:
                proxies = {'http': proxy,'https': proxy}
                try:
                    response = requests.get("https://api.github.com/", proxies=proxies, timeout=5)
                    if response.ok:
                        working_proxies.append(proxies)
                        break
                except requests.exceptions.RequestException:
                    pass
                    
    if working_proxies:
        return working_proxies[0]

    else:
        print("None of the proxies are working. Please provide valid proxies.")
        sys.exit(1)

def validation(url):
    if validators.url(url):
        return True
    else:
        return False

def version():
    return "v0.9.0"

def main():
    banner_printed = False
    parser = argparse.ArgumentParser(prog='CorsOne', description='Check CORS vulnerability', epilog='Verion: 0.9.0')
    parser.add_argument('-u', '--url', type=str, help="input target url to probe")
    parser.add_argument('-l', '--list', help="input file list of URLs")
    parser.add_argument('-ch', '--custom-headers', type=str, help='custom header to include in all http request in header:value format. -ch "header1: value1\nheader2: value2"')
    parser.add_argument('-rl', '--rate-limit', type=int, help='maximum requests to send per second')
    parser.add_argument('-p', '--proxy', type=str, help='SOCKS and HTTP Proxy to use (eg -p "http://127.0.0.1:8080" or -p "proxylist.txt")')
    parser.add_argument('-s', '--silent', action='store_true', help='show only result in output')
    parser.add_argument('-v', '--version', action='store_true', help='show version of CorsOne')
    parser.add_argument('-nc', '--no-color', action='store_false', help='disable color in output')
    parser.add_argument('-o', '--output', help="file to write output to")
    args = parser.parse_args()

    url = args.url
    list = args.list
    custom_headers = args.custom_headers
    proxy = args.proxy
    rate_limit = args.rate_limit
    silent = args.silent
    version_info = args.version
    no_color = args.no_color
    output = args.output
    stdin = not sys.stdin.isatty()
    
    if url and (stdin or list) or stdin and (url or list):
        print("Error: You cannot provide both stdin input and use the -u flag simultaneously.")
        sys.exit(1)

    elif url:
        if not banner_printed and not silent:
            banner()
            banner_printed = True
        if validation(url):
            Scan(url, custom_headers, proxy, output, silent, no_color, rate_limit)
        elif not validation(url):
            print(f"Error: The provided URL '{url}' is not valid. Please enter a valid URL.")
            sys.exit(1)

    elif list:
        if os.path.exists(list):
            with open(list, "r") as file:
                URLs_list = file.read().splitlines()
                if not banner_printed and not silent:
                    banner()
                    banner_printed = True
                    for item in URLs_list:
                        if validation(item):
                            Scan(item, custom_headers, proxy, output, silent, no_color, rate_limit)
                        elif not validation(item):
                            print(f"Error: The provided URL '{item}' is not valid. Please enter a valid URL.")

    elif stdin:
        for stdin_data in sys.stdin:
            stdin_data = stdin_data.strip()
            if not banner_printed and not silent:
                banner()
                banner_printed = True
            if validation(stdin_data):
                Scan(stdin_data, custom_headers, proxy, output, silent, no_color, rate_limit)
            elif not validation(stdin_data):
                print(f"Error: The provided URL '{stdin_data}' is not valid. Please enter a valid URL.")

    elif version_info:
        print(version())

if __name__ == "__main__":
    main()
