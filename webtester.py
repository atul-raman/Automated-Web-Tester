import requests
import re
import sys
import getopt
from termcolor import colored
import shutup
shutup.please()
import os
import math
from threading import Thread
from prettytable import PrettyTable

class Directory:
    def __init__(self, url, httpcode, size):
        self.url = url
        self.httpcode = httpcode
        self.size = size

foundDirectories = []

def main(argv):
    url = ""
    bruteforceFile = ""
    try:
        opts, args = getopt.getopt(argv, "u:b:h", ["url=", "bruteforce=", "help"])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-b", "--bruteforce"):
            bruteforceFile = arg

    if not url:
        print(colored("URL is required. Use -u <url> to specify the URL.", 'red'))
        print_usage()
        sys.exit(2)
    
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(colored(f"Error: {e}", 'red'))
        sys.exit(1)
    
    print("Root Directory Header Vulnerability Scan:")
    perform_header_scan(response)
    
    if bruteforceFile:
        print(f"Starting Bruteforce Attack on {url} using {bruteforceFile} as dictionary.")
        status = directory_bruteforce(url, bruteforceFile)
        if status:
            interactive_scan(url)

def print_usage():
    usage_text = '''Usage: script.py -u <url> [-b <bruteforce file>] [-h]
    -u, --url        Specify the URL
    -b, --bruteforce Enable brute force mode with specified dictionary file
    -h, --help       Display this help message'''
    print(colored(usage_text, 'light_yellow'))

def perform_header_scan(response):
    check_hsts_header(response)
    check_csp_header(response)
    check_xss_header(response)
    check_content_sniffing(response)
    check_permitted_cross_domain_header(response)
    check_xframe_options(response)
    check_expect_ct(response)
    check_feature_policy(response)
    check_referrer_policy(response)

def extract_max_age(header_value):
    match = re.search(r'max-age=(\d+)', header_value)
    if match:
        return int(match.group(1))
    raise ValueError("max-age not found in the header")

def check_hsts_header(response):
    headers = response.headers
    if 'strict-transport-security' in headers:
        try:
            max_age = extract_max_age(headers.get('strict-transport-security'))
            if max_age >= 31536000:
                print(colored(f"HSTS Header is in place with valid max_age value of {max_age}", 'green'))
            else:
                print(colored(f"HSTS Header is in place with invalid max_age value of {max_age}", 'yellow'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("HSTS Header is Not In Place", 'red'))

def check_csp_header(response):
    headers = response.headers
    if 'content-security-policy' in headers:
        csp_header = headers.get('content-security-policy')
        if "unsafe-inline" in csp_header:
            print(colored(f"CSP Header is in place with the usage of unsafe-inline directive.", 'red'))
        else:
            print(colored(f"CSP Header is in place without the usage of unsafe-inline directive.", 'green'))
    else:
        print(colored("CSP Header is Not In Place", 'yellow'))

def check_xss_header(response):
    headers = response.headers
    if 'x-xss-protection' in headers:
        xss_header = headers.get('x-xss-protection')
        if xss_header.startswith('0'):
            print(colored(f"X-XSS-Protection Header is in place but XSS filter is disabled", 'yellow'))
        elif xss_header.startswith('1'):
            print(colored(f"X-XSS-Protection Header and XSS filter is enabled", 'green'), end="")
            if 'block' in xss_header:
                print(colored(" mode is set to block.", 'green'))
            else:
                print(colored(" mode is not set to block.", 'red'))
    else:
        print(colored("X-XSS-Protection Header is Not In Place", 'red'))

def check_content_sniffing(response):
    headers = response.headers
    if 'x-content-type-options' in headers:
        content_type_header = headers.get('x-content-type-options')
        if content_type_header.lower() == "nosniff":
            print(colored(f"X-Content-Type-Options Header is in place set to nosniff", 'green'))
        else:
            print(colored(f"X-Content-Type-Options Header is in place but not set to nosniff", 'yellow'))
    else:
        print(colored("X-Content-Type-Options Header is Not In Place", 'red'))

def check_permitted_cross_domain_header(response):
    headers = response.headers
    if 'x-permitted-cross-domain-policies' in headers:
        cross_domain_header = headers.get('x-permitted-cross-domain-policies')
        if cross_domain_header.lower() == "none":
            print(colored(f"X-Permitted-Cross-Domain-Policies Header is set to none", 'green'))
        else:
            print(colored(f"X-Permitted-Cross-Domain-Policies Header is not set to none", 'red'))
    else:
        print(colored("X-Permitted-Cross-Domain-Policies Header is Not In Place", 'yellow'))

def check_xframe_options(response):
    headers = response.headers
    if 'x-frame-options' in headers:
        xframe_header = headers.get('x-frame-options')
        if xframe_header.lower() == "deny":
            print(colored(f"X-Frame-Options Header is set to deny", 'green'))
        elif xframe_header.lower() == "sameorigin":
            print(colored(f"X-Frame-Options Header is set to sameorigin", 'yellow'))
    else:
        print(colored("X-Frame-Options Header is Not In Place", 'red'))

def check_expect_ct(response):
    if 'expect-ct' in response.headers:
        expect_ct_header = response.headers.get('expect-ct')
        print(colored(f"Expect-CT Header is set to {expect_ct_header}", 'green'))
    else:
        print(colored("Expect-CT Header is Not In Place", 'yellow'))

def check_feature_policy(response):
    if 'feature-policy' in response.headers:
        feature_policy_header = response.headers.get('feature-policy')
        print(colored(f"Feature-Policy Header is set to {feature_policy_header}", 'green'))
    else:
        print(colored("Feature-Policy Header is Not In Place", 'yellow'))

def check_referrer_policy(response):
    if 'referrer-policy' in response.headers:
        referrer_policy_header = response.headers.get('referrer-policy')
        print(colored(f"Referrer-Policy Header is set to {referrer_policy_header}", 'green'))
    else:
        print(colored("Referrer-Policy Header is Not In Place", 'yellow'))

def print_directory_table():
    table = PrettyTable()
    table.field_names = ["Index", "Directory", "HTTP Response Code", "Size (bytes)"]

    sorted_directories = sorted(foundDirectories, key=lambda x: x.size)
    
    for i, directory in enumerate(sorted_directories, start=1):
        color = 'green' if directory.size <= 10000 else 'yellow' if directory.size <= 50000 else 'red'
        table.add_row([i, directory.url, directory.httpcode, colored(directory.size, color)])
    
    print(table)

def directory_bruteforce(url, directories_file):
    max_threads = 10
    try:
        with open(directories_file, "r") as file:
            wordlist = file.read().splitlines()
        
        if not wordlist:
            print(colored("The wordlist is empty.", 'red'))
            return False
        
        num_threads = min(max_threads, len(wordlist))
        chunk_size = math.ceil(len(wordlist) / num_threads)
        lists = [wordlist[i * chunk_size:(i + 1) * chunk_size] for i in range(num_threads)]
        
        threads = []
        for i in range(num_threads):
            thread = Thread(target=bruteforce_function, args=(url, lists[i], i))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

        if not foundDirectories:
            print(colored("No directories were found.", 'red'))
            return False
        else:
            print(colored("Printing found directories:", 'green'))
            for directory in foundDirectories:
                print(directory.url)
            return True
    except IOError as e:
        print(colored(e, 'red'))
        return False
    except KeyboardInterrupt:
        if not foundDirectories:
            print(colored("Search interrupted. No directories were found.", 'red'))
        else:
            print(colored("Search interrupted. Printing found directories:", 'yellow'))
            for directory in foundDirectories:
                print(directory.url)
        return False

def bruteforce_function(url, directories, thread_number):
    session = requests.Session()
    total_lines = len(directories)

    for count, directory in enumerate(directories, start=1):
        percent_done = (count / total_lines) * 100
        if count % 10 == 0:
            print(colored(f"[*][Thread {thread_number}] Progress: {round(percent_done, 2)}%", 'blue'))
        
        directory_url = f"{url}/{directory}"
        response = session.get(directory_url)
        
        if response.status_code in [200, 301, 403, 401, 500]:
            print(colored(f"[+] Found directory: {directory_url}", 'green'))
            foundDirectories.append(Directory(directory_url, response.status_code, len(response.content)))
        else:
            print(colored(f"[-] {directory_url}", 'red'))

def interactive_scan(url):
    while True:
        sorted_directories = sorted(foundDirectories, key=lambda x: x.size)
        print_directory_table()
        target = input("(Enter 0 to quit) Select a target: ")
        
        if target.isdigit():
            target = int(target)
            if target == 0:
                print("Quitting")
                break
            elif 1 <= target <= len(sorted_directories):
                target_url = sorted_directories[target - 1].url
                response = requests.get(target_url)
                print(f"Executing Header Vulnerability Scan: {target_url}")
                perform_header_scan(response)
            else:
                print(colored("Invalid Input", 'red'))
        else:
            print(colored("Invalid Input", 'red'))

if __name__ == "__main__":
    main(sys.argv[1:])
