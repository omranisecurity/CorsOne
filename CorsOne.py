#!/usr/bin/env python3
"""
CorsOne - CORS Misconfiguration Discovery Tool
A fast, reliable, and feature-rich CORS vulnerability scanner.

Usage:
    python3 CorsOne.py -u https://example.com
    python3 CorsOne.py -l targets.txt -w 10
    cat domains.txt | python3 CorsOne.py -w 20

Version: 1.0.0
Author: Mohammad Reza Omrani
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from time import sleep
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import unquote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import validators
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from urllib3.exceptions import ProtocolError, InsecureRequestWarning
from requests.exceptions import RequestException, Timeout, ConnectionError
from urllib3.util.retry import Retry
from threading import Lock

# Suppress SSL warnings
urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.WARNING)

# Initialize colorama
init(autoreset=True)

# Global locks for thread-safe operations
output_lock = Lock()
log_lock = Lock()


# ============================================================================
# Configuration & Data Classes
# ============================================================================

@dataclass
class ScanResult:
    """Represents a single CORS bypass test result."""
    url: str
    bypass_name: str
    bypass_value: str
    is_vulnerable: bool
    response_code: int = 0
    acac: Optional[str] = None
    acao: Optional[str] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=__import__('time').time)

    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        result = asdict(self)
        # Remove None values from output
        return {k: v for k, v in result.items() if v is not None}

    def __str__(self) -> str:
        """String representation."""
        status = '[VULNERABLE]' if self.is_vulnerable else '[SAFE]'
        return f"{self.url} {status} {self.bypass_name}: {self.bypass_value}"


@dataclass
class ScanConfig:
    """Configuration for CORS vulnerability scanning."""
    url: str
    method: str = "GET"
    custom_domain: str = "attacker.com"
    rate_limit: float = 0.0
    timeout: int = 10
    retries: int = 3
    backoff_factor: float = 0.5
    max_workers: int = 5
    stop_on_first: bool = False
    no_color: bool = False
    output_file: Optional[str] = None
    output_format: str = "txt"
    output_log: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    proxy: Optional[Dict[str, str]] = None
    verbose: bool = False
    vulnerable_only: bool = False


class CORSBypassPayloads:
    """CORS bypass payload generation and management."""

    @staticmethod
    def generate(origin: str, malicious_domain: str) -> Dict[str, str]:
        """
        Generate CORS bypass payloads dynamically.
        
        Args:
            origin: Target domain origin
            malicious_domain: Attacker domain for bypass attempts
            
        Returns:
            Dictionary of bypass names and their payloads
        """
        return {
            'Reflected Origin': f'https://{malicious_domain}',
            'Breaking TLS': f'http://{origin}',
            'Trusted Subdomains': f'https://subdomain.{origin}',
            'Unencrypted Subdomains': f'http://subdomain.{origin}',
            'Null Origin': 'null',
            'Unencrypted domain ends allow': f'http://attacker{origin}',
            'Domain ends allow': f'https://attacker{origin}',
            'Unencrypted localhost regex': f'http://localhost.{malicious_domain}',
            'Localhost regex': f'https://localhost.{malicious_domain}',
            'Bypass 1': f'http://{malicious_domain}.{origin}',
            'Bypass 2': f'https://{malicious_domain}.{origin}',
            'Bypass 3': f'https://{origin}._.{malicious_domain}',
            'Bypass 4': f'https://{origin}.-.{malicious_domain}',
            'Bypass 5': f'https://{origin}.,.{malicious_domain}',
            'Bypass 6': f'https://{origin}.;.{malicious_domain}',
            'Bypass 7': f'https://{origin}.!.{malicious_domain}',
            'Bypass 8': f"https://{origin}.' .{malicious_domain}",
            'Bypass 9': f'https://{origin}".{malicious_domain}',
            'Bypass 10': f'https://{origin}.({malicious_domain}',
            'Bypass 11': f'https://{origin}.){malicious_domain}',
            'Bypass 12': f'https://{origin}' + '.{' + f'{malicious_domain}',
            'Bypass 13': f'https://{origin}' + '.}' + f'{malicious_domain}',
            'Bypass 14': f'https://{origin}.*.{malicious_domain}',
            'Bypass 15': f'https://{origin}.&.{malicious_domain}',
            'Bypass 16': f'https://{origin}.`.{malicious_domain}',
            'Bypass 17': f'https://{origin}.+.{malicious_domain}',
            'Bypass 18': f'https://{origin}.{malicious_domain}',
            'Bypass 19': f'https://{origin}.=.{malicious_domain}',
            'Bypass 20': f'https://{origin}.~.{malicious_domain}',
            'Bypass 21': f'https://{origin}.$.{malicious_domain}',
            'Bypass 22': f'http://s{origin}',
            'Bypass 23': f'https://{origin.replace(".", "x")}',
            'Regexp bypass 1': f'{origin},.{malicious_domain}',
            'Regexp bypass 2': f'{origin}&.{malicious_domain}',
            'Regexp bypass 3': f"{origin}'.{malicious_domain}",
            'Regexp bypass 4': f'{origin}".{malicious_domain}',
            'Regexp bypass 5': f'{origin};.{malicious_domain}',
            'Regexp bypass 6': f'{origin}!.{malicious_domain}',
            'Regexp bypass 7': f'{origin}$.{malicious_domain}',
            'Regexp bypass 8': f'{origin}^.{malicious_domain}',
            'Regexp bypass 9': f'{origin}*.{malicious_domain}',
            'Regexp bypass 10': f'{origin}(.{malicious_domain}',
            'Regexp bypass 11': f'{origin}).{malicious_domain}',
            'Regexp bypass 12': f'{origin}+.{malicious_domain}',
            'Regexp bypass 13': f'{origin}=.{malicious_domain}',
            'Regexp bypass 14': f'{origin}`.{malicious_domain}',
            'Regexp bypass 15': f'{origin}~.{malicious_domain}',
            'Regexp bypass 16': f'{origin}-.{malicious_domain}',
            'Regexp bypass 17': f'{origin}_.{malicious_domain}',
            'Regexp bypass 18': f'{origin}|.{malicious_domain}',
            'Regexp bypass 19': f'https://{origin}' + '.{' + f'{malicious_domain}',
            'Regexp bypass 21': f'{origin}%.{malicious_domain}',
        }


class LoggerManager:
    """Centralized logging management."""

    _instance: Optional[LoggerManager] = None
    
    def __new__(cls) -> LoggerManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize logger."""
        if not hasattr(self, '_initialized'):
            self.logger = logging.getLogger('CorsOne')
            self._initialized = True

    def setup(self, verbose: bool = False, log_file: Optional[str] = None):
        """
        Setup logging configuration.
        
        Args:
            verbose: Enable verbose logging
            log_file: Optional file to write logs to (only creates if specified)
        """
        level = logging.DEBUG if verbose else logging.INFO
        self.logger.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        if not self.logger.handlers:
            self.logger.addHandler(console_handler)
        
        # File handler only if log_file is specified
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except IOError as e:
                self.logger.warning(f"Could not create log file: {e}")

    def get_logger(self) -> logging.Logger:
        """Get configured logger instance."""
        return self.logger


class HTTPSessionManager:
    """Manages HTTP sessions with retry logic and connection pooling."""

    def __init__(self, config: ScanConfig):
        """
        Initialize session manager.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """
        Create optimized requests session with retry logic.
        
        Returns:
            Configured requests Session
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'POST', 'HEAD']
        )
        
        # Use HTTPAdapter for connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session

    def close(self):
        """Close session and cleanup."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class CORSVulnerabilityScanner:
    """Main CORS vulnerability scanner."""

    def __init__(self, config: ScanConfig):
        """
        Initialize scanner.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.logger = LoggerManager().get_logger()
        self.session_manager = HTTPSessionManager(config)
        self.results: List[ScanResult] = []
        self.vulnerable_results: List[ScanResult] = []
        self.error_count: int = 0
        self.http_status_codes: Dict[int, int] = {}

    def test_bypass(self, url: str, bypass_name: str, bypass_value: str) -> ScanResult:
        """
        Test a single CORS bypass technique.
        
        Args:
            url: Target URL
            bypass_name: Name of bypass technique
            bypass_value: Bypass payload value
            
        Returns:
            ScanResult object with test outcome
        """
        try:
            headers = self.session_manager.session.headers.copy()
            headers['Origin'] = bypass_value
            
            # Add custom headers if provided
            if self.config.custom_headers:
                headers.update(self.config.custom_headers)
            
            response = self.session_manager.session.request(
                self.config.method,
                url,
                headers=headers,
                proxies=self.config.proxy,
                timeout=self.config.timeout,
                allow_redirects=False
            )
            
            acac = response.headers.get('Access-Control-Allow-Credentials')
            acao = response.headers.get('Access-Control-Allow-Origin')
            
            is_vulnerable = bool(acac == 'true' and acao == bypass_value)
            
            # Track HTTP status codes
            status_code = response.status_code
            self.http_status_codes[status_code] = self.http_status_codes.get(status_code, 0) + 1
            
            result = ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=is_vulnerable,
                response_code=status_code,
                acac=acac,
                acao=acao
            )
            
            self._print_result(result)
            
            if self.config.rate_limit:
                sleep(self.config.rate_limit)
            
            return result
            
        except (Timeout, ConnectionError) as e:
            self.logger.warning(f"Network error for {bypass_name}: {e}")
            self.error_count += 1
            return ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=False,
                error=f"Network error: {str(e)}"
            )
        except RequestException as e:
            self.logger.warning(f"Request error for {bypass_name}: {e}")
            self.error_count += 1
            return ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=False,
                error=f"Request error: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error for {bypass_name}: {e}")
            self.error_count += 1
            return ScanResult(
                url=url,
                bypass_name=bypass_name,
                bypass_value=bypass_value,
                is_vulnerable=False,
                error=f"Unexpected error: {str(e)}"
            )

    def _print_result(self, result: ScanResult):
        """
        Print result with appropriate formatting.
        
        Args:
            result: ScanResult to print
        """
        if self.config.vulnerable_only and not result.is_vulnerable:
            return

        with output_lock:
            status = '[VULNERABLE]' if result.is_vulnerable else '[SAFE]'
            output = f"{status} {result.bypass_name}: {result.bypass_value}"
            
            if self.config.no_color:
                print(output)
            else:
                color = Fore.GREEN if result.is_vulnerable else Fore.RED
                print(f"{color}{output}{Style.RESET_ALL}")

    def scan(self) -> Tuple[List[ScanResult], int]:
        """
        Perform comprehensive CORS vulnerability scan.
        
        Returns:
            Tuple of (all_results, vulnerable_count)
        """
        url = unquote(self.config.url, encoding='utf-8')
        origin = urlparse(url).netloc
        
        if self.config.verbose:
            self.logger.info(f"Starting scan on {url}")
            self.logger.info(f"Using {self.config.max_workers} workers")
        
        payloads = CORSBypassPayloads.generate(origin, self.config.custom_domain)
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {
                    executor.submit(self.test_bypass, url, name, value): (name, value)
                    for name, value in payloads.items()
                }
                
                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        result = future.result()
                        self.results.append(result)
                        
                        if result.is_vulnerable:
                            self.vulnerable_results.append(result)
                            
                            if self.config.stop_on_first:
                                self.logger.info("Vulnerability found, stopping scan")
                                for f in futures:
                                    f.cancel()
                                break
                        
                        if self.config.verbose and i % 10 == 0:
                            self.logger.info(f"Progress: {i}/{len(payloads)}")
                            
                    except Exception as e:
                        self.logger.error(f"Error processing result: {e}")
        
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            sys.exit(0)
        finally:
            self.session_manager.close()
        
        return self.results, len(self.vulnerable_results)

    def save_results(self):
        """Save results to output file in specified format."""
        if not self.config.output_file:
            return
        
        try:
            output_path = Path(self.config.output_file)
            output_format = self.config.output_format.lower()

            if output_format not in ['json', 'txt']:
                self.logger.error(f"Unsupported format: {output_format}. Use 'txt' or 'json'.")
                return

            final_path = output_path.with_suffix('.json' if output_format == 'json' else '.txt')

            if output_format == 'json':
                results_to_save = [r.to_dict() for r in self.results if not self.config.vulnerable_only or r.is_vulnerable]
                with open(final_path, 'w') as f:
                    json.dump(
                        results_to_save,
                        f,
                        indent=2,
                        default=str
                    )
                self.logger.info(f"Results saved to {final_path}")
            else:
                with open(final_path, 'w') as f:
                    if self.config.vulnerable_only:
                        results_to_save = [r for r in self.results if r.is_vulnerable]
                    elif self.config.stop_on_first and self.vulnerable_results:
                        results_to_save = [self.vulnerable_results[0]]
                    else:
                        results_to_save = self.results

                    for result in results_to_save:
                        f.write(str(result) + '\n')
                self.logger.info(f"Results saved to {final_path}")

        except IOError as e:
            self.logger.error(f"Failed to save results: {e}")

    def print_summary(self):
        """Print scan summary."""
        total = len(self.results)
        vulnerable = len(self.vulnerable_results)
        safe = total - vulnerable - self.error_count
        
        # Helper function to apply color if enabled
        def colorize(text: str, color) -> str:
            if self.config.no_color:
                return text
            return f"{color}{text}{Style.RESET_ALL}"
        
        print(f"\n{'='*70}")
        print(f"{'SCAN SUMMARY':^70}")
        print(f"{'='*70}")
        print(f"Total tests:          {total}")
        print(f"Vulnerable:           {colorize(str(vulnerable), Fore.GREEN)}")
        print(f"Safe:                 {colorize(str(safe), Fore.RED)}")
        print(f"Errors:               {colorize(str(self.error_count), Fore.YELLOW)}")
        
        if self.http_status_codes:
            print(f"\n{colorize('HTTP Status Codes:', Fore.CYAN)}")
            for status_code in sorted(self.http_status_codes.keys()):
                count = self.http_status_codes[status_code]
                print(f"  • {status_code}: {count}")
        
        if vulnerable > 0:
            print(f"\n{colorize('Vulnerable bypasses:', Fore.GREEN)}")
            for result in self.vulnerable_results:
                print(f"  • {result.bypass_name}: {result.bypass_value}")
        
        print(f"{'='*70}\n")


class URLValidator:
    """URL validation and normalization."""

    @staticmethod
    def validate(url: str) -> str:
        """
        Validate and normalize URL.
        
        Args:
            url: URL to validate
            
        Returns:
            Validated URL
            
        Raises:
            ValueError: If URL is invalid
        """
        url = url.strip()
        
        if validators.url(url):
            return url
        elif validators.domain(url):
            return f'https://{url}'
        else:
            raise ValueError(f"Invalid URL: {url}")


class DomainValidator:
    """Validates that custom domain is a base domain without protocol or subdomain."""

    @staticmethod
    def validate(domain: str) -> str:
        """
        Validate custom domain.
        
        Args:
            domain: Domain to validate
            
        Returns:
            Validated domain
            
        Raises:
            ValueError: If domain is invalid
        """
        domain = domain.strip()
        
        # Check for protocol prefixes
        if domain.startswith('http://') or domain.startswith('https://'):
            raise ValueError("Custom domain should not include 'http://' or 'https://' protocol")
        
        # Check if it contains subdomain (multiple dots)
        parts = domain.split('.')
        if len(parts) < 2:
            raise ValueError("Custom domain must be a valid domain (e.g., example.com)")
        
        # Validate domain format
        if validators.domain(domain):
            return domain
        else:
            raise ValueError(f"Invalid domain format: {domain}")


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser.
    
    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog='CorsOne',
        description='CORS Misconfiguration Discovery Tool',
        epilog='Version: 1.0.0 | https://github.com/omranisecurity/CorsOne',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target input
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-u', '--url', help='Target URL to scan')
    input_group.add_argument('-l', '--list', help='File with URLs (one per line)')
    
    # Scanning options
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET',
                       help='HTTP method (default: GET)')
    parser.add_argument('-sof', '--stop-on-first', action='store_true',
                       help='Stop after finding first vulnerability')
    parser.add_argument('-cd', '--custom-domain', default='attacker.com',
                       help='Custom domain for payloads (default: attacker.com)')
    parser.add_argument('-ch', '--custom-headers', help='Custom headers as JSON')
    parser.add_argument('-p', '--proxy', help='Proxy URL (socks5://host:port)')
    
    # Performance options
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of concurrent workers (default: 5)')
    parser.add_argument('-rl', '--rate-limit', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-r', '--retries', type=int, default=3,
                       help='Number of retries for failed requests (default: 3)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-f', '--format', choices=['txt', 'json'], default='txt',
                       help='Output format (txt or json). Default: txt. Explicit --format always takes precedence over output file extension.')
    parser.add_argument('--log', help='Log file path. Only creates log file if specified.')
    parser.add_argument('-vo', '--vuln-only', action='store_true',
                       help='Show and save only vulnerable endpoints')
    parser.add_argument('-nc', '--no-color', action='store_true',
                       help='Disable colored output')
    parser.add_argument('-s', '--silent', action='store_true',
                       help='Silent mode (no banner)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose logging')
    
    # Utility options
    parser.add_argument('--version', action='store_true', help='Show version')
    
    return parser


def print_banner():
    """Print tool banner."""
    banner_text = """
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                                          ┃
    ┃                        CorsOne                           ┃
    ┃         CORS Misconfiguration Discovery Tool v1.0        ┃
    ┃                                                          ┃
    ┃               Fast | Reliable | Feature-Rich             ┃
    ┃                                                          ┃
    ┃        https://github.com/omranisecurity/CorsOne         ┃
    ┃                                                          ┃
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """
    print(banner_text)


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle version
    if args.version:
        print("CorsOne v1.0.0")
        sys.exit(0)
    
    # Setup logging
    logger = LoggerManager()
    logger.setup(verbose=args.verbose, log_file=args.log)
    
    # Print banner unless silent
    if not args.silent:
        print_banner()
    
    # Collect URLs
    urls: List[str] = []
    
    if args.url:
        urls = [args.url]
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.get_logger().error(f"Failed to read URL list: {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)
    
    # Parse custom headers if provided
    custom_headers: Optional[Dict[str, str]] = None
    if args.custom_headers:
        try:
            custom_headers = json.loads(args.custom_headers)
        except json.JSONDecodeError:
            logger.get_logger().error("Invalid JSON for custom headers")
            sys.exit(1)
    
    # Parse proxy if provided
    proxy: Optional[Dict[str, str]] = None
    if args.proxy:
        proxy = {'http': args.proxy, 'https': args.proxy}
    
    # Validate custom domain
    try:
        custom_domain = DomainValidator.validate(args.custom_domain)
    except ValueError as e:
        logger.get_logger().error(f"{e}")
        sys.exit(1)
    
    # Process each URL
    for url_input in urls:
        try:
            url = URLValidator.validate(url_input)
        except ValueError as e:
            logger.get_logger().error(f"{e}")
            continue
        
        # Create configuration
        config = ScanConfig(
            url=url,
            method=args.method,
            custom_domain=custom_domain,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            retries=args.retries,
            max_workers=args.workers,
            stop_on_first=args.stop_on_first,
            no_color=args.no_color,
            output_file=args.output,
            output_format=args.format,
            output_log=args.log,
            custom_headers=custom_headers,
            proxy=proxy,
            verbose=args.verbose,
            vulnerable_only=args.vuln_only
        )
        
        # Run scanner
        scanner = CORSVulnerabilityScanner(config)
        results, vulnerable_count = scanner.scan()
        
        # Save and display results
        scanner.save_results()
        if not args.silent:
            scanner.print_summary()


if __name__ == '__main__':
    main()
