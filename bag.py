import os
import time
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Warna untuk tampilan
COLOR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "END": "\033[0m",
    "BOLD": "\033[1m"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    clear_screen()
    print(f"""{COLOR['HEADER']}
    ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
    ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
    ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
    ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
    ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
    ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
    {COLOR['END']}{COLOR['BOLD']}v1.0 | Created by x dev{COLOR['END']}
    """)

def display_menu():
    print(f"""
    {COLOR['GREEN']}[1]{COLOR['END']} Scan Website Vulnerability (Deep Scan)
    {COLOR['GREEN']}[2]{COLOR['END']} About Program
    {COLOR['GREEN']}[3]{COLOR['END']} Exit
    """)

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def deep_scan(target):
    print(f"\n{COLOR['BLUE']}[+] Starting deep scan on {target}{COLOR['END']}\n")
    time.sleep(1)
    
    vulnerabilities = []
    
    # 1. Check HTTP headers and server info
    try:
        print(f"{COLOR['BLUE']}[+] Checking HTTP headers...{COLOR['END']}")
        response = requests.get(target, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        headers = response.headers
        
        # Check for sensitive headers
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for header in sensitive_headers:
            if header in headers:
                vuln = f"Server info exposed in {header}: {headers[header]}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
                
        # Check security headers
        security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options', 
                           'content-security-policy', 'strict-transport-security']
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            vuln = f"Missing security headers: {', '.join(missing_headers)}"
            print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)
            
    except Exception as e:
        print(f"{COLOR['RED']}[!] Error checking headers: {str(e)}{COLOR['END']}")
    
    # 2. Check for sensitive files
    print(f"\n{COLOR['BLUE']}[+] Checking for sensitive files...{COLOR['END']}")
    sensitive_files = [
        'robots.txt', '.env', 'config.php', 'database.db', 'backup.zip',
        'wp-config.php', 'settings.ini', 'web.config', '.git/config',
        '.htaccess', 'phpinfo.php', 'adminer.php', 'dump.sql',
        'backup.tar.gz', 'credentials.json', 'config.json'
    ]
    
    for file in sensitive_files:
        try:
            url = f"{target}/{file}" if target.endswith('/') else f"{target}/{file}"
            res = requests.get(url, timeout=10, allow_redirects=False)
            
            if res.status_code == 200:
                vuln = f"Sensitive file exposed: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
                
                # If it's a database file, check if we can download it
                if file.endswith(('.db', '.sql', '.zip', '.tar.gz')):
                    try:
                        content = res.content
                        if len(content) > 0:
                            vuln = f"Database/backup file downloadable: {url} (Size: {len(content)} bytes)"
                            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
                            vulnerabilities.append(vuln)
                    except:
                        pass
                        
        except:
            pass
    
    # 3. Check directory listing
    print(f"\n{COLOR['BLUE']}[+] Checking for directory listing...{COLOR['END']}")
    test_dirs = ['images/', 'uploads/', 'assets/', 'backup/', 'admin/']
    for directory in test_dirs:
        try:
            url = f"{target}/{directory}" if target.endswith('/') else f"{target}/{directory}"
            res = requests.get(url, timeout=10)
            
            # Simple check for directory listing
            if "Index of /" in res.text or "Directory listing for /" in res.text:
                vuln = f"Directory listing enabled: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
        except:
            pass
    
    # 4. Check common admin panels
    print(f"\n{COLOR['BLUE']}[+] Checking for admin panels...{COLOR['END']}")
    admin_panels = [
        'admin/', 'wp-admin/', 'administrator/', 'login/', 
        'dashboard/', 'manager/', 'admin.php', 'admin.asp'
    ]
    
    for panel in admin_panels:
        try:
            url = f"{target}/{panel}" if target.endswith('/') else f"{target}/{panel}"
            res = requests.get(url, timeout=10, allow_redirects=False)
            
            if res.status_code == 200:
                vuln = f"Admin panel found: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
        except:
            pass
    
    # 5. Check for SQL injection vulnerability (basic check)
    print(f"\n{COLOR['BLUE']}[+] Checking for basic SQLi vulnerability...{COLOR['END']}")
    try:
        test_url = f"{target}/product?id=1'"
        res = requests.get(test_url, timeout=15)
        
        sql_errors = [
            "SQL syntax", "MySQL server", "syntax error", "unclosed quotation mark",
            "ODBC Driver", "ORA-", "PostgreSQL", "Microsoft OLE DB Provider"
        ]
        
        if any(error in res.text for error in sql_errors):
            vuln = f"Possible SQL injection vulnerability at: {test_url}"
            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)
    except:
        pass
    
    # 6. Check for XSS vulnerability (basic check)
    print(f"\n{COLOR['BLUE']}[+] Checking for basic XSS vulnerability...{COLOR['END']}")
    try:
        test_url = f"{target}/search?q=<script>alert('XSS')</script>"
        res = requests.get(test_url, timeout=15)
        
        if "<script>alert('XSS')</script>" in res.text:
            vuln = f"Possible XSS vulnerability at: {test_url}"
            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)
    except:
        pass
    
    # 7. Check for open ports
    print(f"\n{COLOR['BLUE']}[+] Checking for open ports...{COLOR['END']}")
    try:
        domain = urlparse(target).netloc.split(':')[0]
        ports_to_check = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443]
        
        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                vuln = f"Port {port} is open"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
            sock.close()
    except Exception as e:
        print(f"{COLOR['RED']}[!] Error checking ports: {str(e)}{COLOR['END']}")
    
    return vulnerabilities

def generate_report(target, vulnerabilities):
    if not vulnerabilities:
        print(f"\n{COLOR['GREEN']}[✓] No obvious vulnerabilities found{COLOR['END']}")
        return
    
    print(f"\n{COLOR['RED']}[!] Found {len(vulnerabilities)} vulnerabilities:{COLOR['END']}")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f" {i}. {vuln}")
    
    print(f"\n{COLOR['BLUE']}[+] Security recommendations:{COLOR['END']}")
    print(" 1. Remove or restrict access to sensitive files")
    print(" 2. Disable directory listing in server configuration")
    print(" 3. Implement proper security headers")
    print(" 4. Sanitize all user inputs to prevent SQLi/XSS")
    print(" 5. Close unnecessary ports")
    print(" 6. Hide server version information")
    print(" 7. Implement rate limiting and WAF")
    print(" 8. Regularly update all software components")

def about_program():
    display_header()
    print(f"""
    {COLOR['BLUE']}[ About Bug Bounty Scanner ]{COLOR['END']}
    
    This is a comprehensive web vulnerability scanner designed to help
    security researchers and bug bounty hunters identify common security
    issues in web applications.
    
    {COLOR['BOLD']}Features:{COLOR['END']}
    - Sensitive file detection (config files, databases, backups)
    - Directory listing checks
    - Admin panel discovery
    - Basic SQL injection testing
    - Basic XSS testing
    - Open port scanning
    - HTTP header analysis
    - Detailed security recommendations
    
    {COLOR['BOLD']}Note:{COLOR['END']}
    - Always get proper authorization before scanning any website
    - This tool is for educational and ethical testing purposes only
    - Not all findings may be actual vulnerabilities (false positives possible)
    
    Created by: x dev
    Version: 1.0
    """)
    input("\nPress Enter to return to menu...")

def main():
    while True:
        display_header()
        display_menu()
        
        choice = input(f"{COLOR['BOLD']}Select option [1-3]: {COLOR['END']}")
        
        if choice == "1":
            display_header()
            print(f"{COLOR['BLUE']}[ Website Vulnerability Scanner ]{COLOR['END']}\n")
            target = input("Enter website URL (e.g., https://example.com): ").strip()
            
            if not validate_url(target):
                print(f"\n{COLOR['RED']}[!] Invalid URL format. Please include http:// or https://{COLOR['END']}")
                time.sleep(2)
                continue
                
            vulnerabilities = deep_scan(target)
            generate_report(target, vulnerabilities)
            
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            about_program()
            
        elif choice == "3":
            print(f"\n{COLOR['GREEN']}[+] Thank you for using Bug Bounty Scanner. Goodbye!{COLOR['END']}")
            break
            
        else:
            print(f"\n{COLOR['RED']}[!] Invalid choice. Please select 1-3.{COLOR['END']}")
            time.sleep(1)

if __name__ == "__main__":
    main()
