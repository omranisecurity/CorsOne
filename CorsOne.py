#!/usr/bin/env python3

from urllib.parse import unquote, urlparse
import argparse
import requests
import validators
import sys
from colorama import Fore, Style, init
from time import sleep
from requests.exceptions import RequestException
from urllib3.exceptions import ProtocolError

# Initialize colorama for colored output
init(autoreset=True)

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

def scan(url, headers, output, no_color, rate_limit, method, stop_on_first, proxy):
    url = unquote(url, encoding='utf-8')
    origin = urlparse(url).netloc
    bypass_dict = {
        'Reflected Origin': 'https://attacker.com',
        'Breaking TLS': f'http://{origin}',
        'Trusted Subdomains': f'https://subdomain.{origin}',
        'Unencrypted Subdomains': f'http://subdomain.{origin}',
        'Null Origin': 'Null',
        'Unencrypted domain ends allow': f'http://attacker{origin}',
        'Domain ends allow': f'https://attacker{origin}',
        'Unencrypted localhost regex implementation edge case': 'http://localhost.attacker.com/',
        'Localhost regex implementation edge case': 'https://localhost.attacker.com/',
        'Bypass 1': f'http://attacker.com.{origin}',
        'Bypass 2': f'https://attacker.com.{origin}',
        'Bypass 3': f'https://{origin}._.attacker.com',
        'Bypass 4': f'https://{origin}.-.attacker.com',
        'Bypass 5': f'https://{origin}.,.attacker.com',
        'Bypass 6': f'https://{origin}.;.attacker.com',
        'Bypass 7': f'https://{origin}.!.attacker.com',
        "Bypass 8": f"https://{origin}.' .attacker.com",
        'Bypass 9': f'https://{origin}".attacker.com',
        'Bypass 10': f'https://{origin}.(.attacker.com',
        'Bypass 11': f'https://{origin}.).attacker.com',
        'Bypass 12': 'https://' + origin + '.{attacker.com',
        'Bypass 13': 'https://' + origin + '.}attacker.com',
        'Bypass 14': f'https://{origin}.*.attacker.com',
        'Bypass 15': f'https://{origin}.&.attacker.com',
        'Bypass 16': f'https://{origin}.`.attacker.com',
        'Bypass 17': f'https://{origin}.+.attacker.com',
        'Bypass 18': f'https://{origin}.attacker.com',
        'Bypass 19': f'https://{origin}.=.attacker.com',
        'Bypass 20': f'https://{origin}.~.attacker.com',
        'Bypass 21': f'https://{origin}.$.attacker.com',
        'Bypass 22': f'http://s{origin}/',
        'Bypass 23': f'https://{origin.replace(".", "x")}',
        'Advance Regexp bypass 1': f'{origin},.attacker.com',
        'Advance Regexp bypass 2': f'{origin}&.attacker.com',
        'Advance Regexp bypass 3': f"{origin}'.attacker.com",
        'Advance Regexp bypass 4': f'{origin}".attacker.com',
        'Advance Regexp bypass 5': f'{origin};.attacker.com',
        'Advance Regexp bypass 6': f'{origin}!.attacker.com',
        'Advance Regexp bypass 7': f'{origin}$.attacker.com',
        'Advance Regexp bypass 8': f'{origin}^.attacker.com',
        'Advance Regexp bypass 9': f'{origin}*.attacker.com',
        'Advance Regexp bypass 10': f'{origin}(.attacker.com',
        'Advance Regexp bypass 11': f'{origin}).attacker.com',
        'Advance Regexp bypass 12': f'{origin}+.attacker.com',
        'Advance Regexp bypass 13': f'{origin}=.attacker.com',
        'Advance Regexp bypass 14': f'{origin}`.attacker.com',
        'Advance Regexp bypass 15': f'{origin}~.attacker.com',
        'Advance Regexp bypass 16': f'{origin}-.attacker.com',
        'Advance Regexp bypass 17': f'{origin}_.attacker.com',
        'Advance Regexp bypass 18': f'{origin}|.attacker.com',
        'Advance Regexp bypass 19': 'https://' + origin + '.{.attacker.com',
        'Advance Regexp bypass 19': 'https://' + origin + '.}.attacker.com',
        'Advance Regexp bypass 21': f'{origin}%.attacker.com',
    }

    vulnerable_found = False
    endpoints = []

    for key, val in bypass_dict.items():
        headers['origin'] = val
        try:
            response = requests.request(method, url, headers=headers, proxies=proxy)
            acac, acao = response.headers.get('Access-Control-Allow-Credentials'), response.headers.get('Access-Control-Allow-Origin')
            status = '[Vulnerable]' if acac and acao == val else '[Not Vulnerable]'
            endpoint = f"{url} {status} {key}: {val}"
            
            # Determine color based on status
            color = Fore.GREEN if status == '[Vulnerable]' else Fore.RED

            if no_color:
                print(endpoint)
            else:
                print(f"{color}{status} {key}: {val}{Style.RESET_ALL}")

            if status == '[Vulnerable]':
                endpoints.append(endpoint)
                if stop_on_first and not vulnerable_found:
                    vulnerable_found = True
                    break

            elif not stop_on_first:
                endpoints.append(endpoint)

            if rate_limit:
                sleep(rate_limit)
                
        except (RequestException, ProtocolError) as e:
            print(f"Request error: {e}")
            continue
        except KeyboardInterrupt:
            print("\nProcess interrupted by user.")
            sys.exit(0)  # Exiting gracefully when interrupted by the user

    if output:
        if stop_on_first and vulnerable_found:
            with open(output, "w") as file:
                file.write(endpoints[0] + "\n")
        elif endpoints:
            with open(output, "w") as file:  # Overwrite the file for non-stop-on-first cases
                file.write("\n".join(endpoints) + "\n")

def validation(url):
    if validators.url(url):
        return url
    elif validators.domain(url):
        return f'https://{url}'
    print(f"Error: The provided URL '{url}' is not valid.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(prog='CorsOne', description='Fast CORS Misconfiguration Discovery Tool', epilog='Version: 0.9.6')
    parser.add_argument('-u', '--url', type=str, help="input target url to probe")
    parser.add_argument('-l', '--list', help="input file list of URLs")
    parser.add_argument('-sof', '--stop-on-first', action='store_true', help='stop testing after finding the first vulnerability')
    parser.add_argument('-ch', '--custom-headers', type=str, help='custom header to include in all http request in header:value format. -ch "header1: value1\\nheader2: value2"')
    parser.add_argument('-p', '--proxy', type=str, help="socks5 proxy in the format socks5://user:pass@host:port")
    parser.add_argument('-rl', '--rate-limit', type=int, help='maximum requests to send per second')
    parser.add_argument('-m', '--method', type=str, choices=['GET', 'POST'], help='HTTP method for the request')
    parser.add_argument('-s', '--silent', action='store_true', help='show only result in output')
    parser.add_argument('-v', '--version', action='store_true', help='show version of CorsOne')
    parser.add_argument('-nc', '--no-color', action='store_true', help='disable color in output')
    parser.add_argument('-o', '--output', help="file to write output to")
    args = parser.parse_args()

    headers = {
        'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    }

    method = args.method if args.method else "GET"

    if args.version:
        print("v0.9.6")
        sys.exit(0)

    # Check if both -u and -l are provided
    if args.url and args.list:
        print("Error: You cannot use both -u (URL) and -l (list of URLs) flags simultaneously.")
        sys.exit(1)

    if args.custom_headers:
        headers.update({k: v.strip() for k, v in (h.split(':', 1) for h in args.custom_headers.replace('\\n', '\n').splitlines())})

    # Handle proxy
    proxy = None
    if args.proxy:
        proxy = {
            'http': args.proxy,
            'https': args.proxy,
        }

    urls = []

    # Read URLs from stdin or list or URL argument
    if not args.url and not args.list and not sys.stdin.isatty():
        urls = sys.stdin.read().splitlines()
    elif args.url:
        urls = [validation(args.url)]
    elif args.list:
        with open(args.list, "r") as file:
            urls = file.read().splitlines()

    # Print banner if not in silent mode
    if not args.silent:
        banner()

    for url in urls:
        scan(validation(url), headers, args.output, args.no_color, args.rate_limit, method, args.stop_on_first, proxy)

if __name__ == '__main__':
    main()
