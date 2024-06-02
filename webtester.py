import requests
import re
import sys, getopt
from termcolor import colored
import shutup; shutup.please()
import os
import matplotlib.pyplot as plt
import numpy as np
from prettytable import PrettyTable
import multiprocessing 
from threading import Thread, Event
import math

class dir:
    def __init__(self, url, httpcode, size):
        self.url = url
        self.httpcode = httpcode
        self.size = size

foundDirectories = []

def main(argv):
    url = ""
    bruteforceFile = ""
    try:
        opts, args = getopt.getopt(argv, "u:b:h", ["url=", "bruteforce", "help"])
    except getopt.GetoptError:
        print(colored('usage: webtester.py -u <url>', 'light_yellow'))
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(colored('Usage: script.py -u <url> [-b] [-h]\n-u, --url       Specify the URL\n-b, --bruteforce Enable brute force mode\n-h, --help', 'light_yellow'))
            sys.exit(1)
        elif opt in ("-u", "--url"):
            url = arg
        if opt in ("-b", "--bruteforce"):
            bruteforceFile = arg
    response = ""

    try:
        response = requests.get(url)
    except requests.exceptions.MissingSchema:
        print(colored("Please include http:// or https:// in the url", 'light_yellow'))
        sys.exit(1)
    except requests.exceptions.InvalidURL:
        print(colored("Please provide a valid url", 'light_yellow'))
        sys.exit(1)
        
    print("Header Vulnerability Scan:")
    checkHSTSHeader(response)
    checkCSPHeader(response)
    checkXSSHeader(response)
    checkContentSniffing(response)
    checkPermittedCrossDomainHeader(response)
    checkXFrameOptions(response)
    checkExpectCT(response)
    checkFeaturePolicy(response)
    checkReferrerPolicy(response)
    
    status = False
    if bruteforceFile != "":
        print(f"Starting Bruteforce Attack on {url} using {bruteforceFile} as dictionary.")
        status = directoryBruteforce(url, bruteforceFile)
        print(status)
    while status == True:
        sortedDirectories = sorted(foundDirectories, key=lambda x: x.size)
        printDirectoryTable()
        target = input("(Enter 0 to quit) Select a target: ")
        if(target.isdigit()):
            if(int(target) == 0):
                print("Quitting")
                status = False
                break
            else:
                if(1 <= int(target) <= len(sortedDirectories)):
                   
                    target = sortedDirectories[int(target) -1].url
                    

                    response = requests.get(target)
                    print(f"Executing Header Vulnerability Scan: {target}")
                    checkHSTSHeader(response)
                    checkCSPHeader(response)
                    checkXSSHeader(response)
                    checkContentSniffing(response)
                    checkPermittedCrossDomainHeader(response)
                    checkXFrameOptions(response)
                    checkExpectCT(response)
                    checkFeaturePolicy(response)
                    checkReferrerPolicy(response)
        
                else:
                    print(colored("Invalid Input",'red'))
        else:
                    print(colored("Invalid Input",'red'))            
            
def extract_max_age(header_value):
    match = re.search(r'max-age=(\d+)', header_value)
    if match:
        return int(match.group(1))
    else:
        raise ValueError("max-age not found in the header")

def checkHSTSHeader(response):
    headers = response.headers
    if 'strict-transport-security' in headers:
        try:
            max_age = extract_max_age(headers.get('Strict-Transport-Security'))
            if int(max_age) >= 31536000:
                print(colored(f"HSTS Header is in place with valid max_age value of {max_age}", 'green'))
            else:
                print(colored(f"HSTS Header is in place with invalid max_age value of {max_age}", 'yellow'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("HSTS Header is Not In Place", 'red'))

def checkCSPHeader(response):
    headers = response.headers
    if 'content-security-policy' in headers:
        try:
            contentSecurityHeader = headers.get('content-security-policy')
            if "unsafe-inline" in contentSecurityHeader:
                print(colored(f"CSP Header is in place with the usage of unsafe-inline directive.", 'red'))
            else:
                print(colored(f"CSP Header is in place without the usage of unsafe-inline directive.", 'green'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("CSP Header is Not In Place", 'yellow'))

def checkXSSHeader(response):
    headers = response.headers
    if 'x-xss-protection' in headers:
        try:
            contentSecurityHeader = headers.get('x-xss-protection')
            if contentSecurityHeader[0] == '0':
                print(colored(f"X-XSS-Protection Header is in place but XSS filter is disabled", 'yellow'))
            elif contentSecurityHeader[0] == '1':
                print(colored(f"X-XSS-Protection Header and XSS filter is enabled", 'green'), end="")
                if 'block' in contentSecurityHeader:
                    print(colored(" mode is set to block.", 'green'))
                else:
                    print(colored(" mode is not set to block.", 'red'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("X-XSS-Protection Header is Not In Place", 'red'))

def checkContentSniffing(response):
    headers = response.headers
    if 'x-content-type-options' in headers:
        try:
            contentTypeHeader = headers.get('x-content-type-options')
            if "nosniff" in contentTypeHeader:
                print(colored(f"X-Content-Type-Options Header is in place set to nosniff", 'green'))
            else:
                print(colored(f"X-Content-Type-Options Header is in place not set to nosniff", 'yellow'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("X-Content-Type-Options Header is Not In Place", 'red'))

def checkPermittedCrossDomainHeader(response):
    headers = response.headers
    if 'x-permitted-cross-domain-policies' in headers:
        try:
            contentSecurityHeader = headers.get('x-permitted-cross-domain-policies')
            if contentSecurityHeader == "none":
                print(colored(f"X-Permitted-Cross-Domain-Policies Header is set to none", 'green'))
            else:
                print(colored(f"X-Permitted-Cross-Domain-Policies Header is not set to none", 'red'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("X-Permitted-Cross-Domain-Policies Header is Not In Place", 'yellow'))

def checkXFrameOptions(response):
    headers = response.headers
    if 'x-frame-options' in headers:
        try:
            header = headers.get('x-frame-options')
            if header == "deny":
                print(colored(f"X-Frame-Options Header is set to deny", 'green'))
            elif header == "sameorigin":
                print(colored(f"X-Frame-Options Header is set to sameorigin", 'yellow'))
        except ValueError as e:
            print(colored(e, 'red'))
    else:
        print(colored("X-Frame-Options Header is Not In Place", 'red'))

def checkExpectCT(response):
    if 'expect-ct' in response.headers:
        header = response.headers.get('expect-ct')
        print(colored(f"Expect-CT Header is set to {header}", 'green'))
    else:
        print(colored("Expect-CT Header is Not In Place", 'yellow'))

def checkFeaturePolicy(response):
    if 'feature-policy' in response.headers:
        header = response.headers.get('feature-policy')
        print(colored(f"Feature-Policy Header is set to {header}", 'green'))
    else:
        print(colored("Feature-Policy Header is Not In Place", 'yellow'))

def checkReferrerPolicy(response):
    if 'referrer-policy' in response.headers:
        header = response.headers.get('referrer-policy')
        print(colored(f"Referrer-Policy Header is set to {header}", 'green'))
    else:
        print(colored("Referrer-Policy Header is Not In Place", 'yellow'))

def printDirectoryTable():
    table = PrettyTable()
    table.field_names = ["Index", "Directory", "HTTP Response Code", "Size (bytes)"]

    # Sort foundDirectories by size before printing
    sortedDirectories = sorted(foundDirectories, key=lambda x: x.size)
    
    for i in range(len(sortedDirectories)):
        directory = sortedDirectories[i].url
        size = sortedDirectories[i].size
        response_code = sortedDirectories[i].httpcode

        color = 'green'
        if size > 10000:
            color = 'yellow'
        if size > 50000:
            color = 'red'
        table.add_row([i+1, directory, response_code, colored(size, color)])
    
    print(table)

def directoryBruteforce(url, directoriesFile):
    max_threads = 10
    try:
        file = open(directoriesFile, "r")
        wordlist = file.read().splitlines()
        count = 0
        totalLines = len(wordlist)
        if totalLines == 0:
            print("The wordlist is empty.")
            return False
        
        num_threads = min(max_threads, totalLines)
        
        chunk_size = math.ceil(totalLines / num_threads)
        lists = [wordlist[i * chunk_size:(i + 1) * chunk_size] for i in range(num_threads)]
        
        
        threads = []
        for i in range(num_threads):
            thread = Thread(target=bruteforceFunction, args=(url, lists[i],i))
            threads.append(thread)
            thread.start()
        
        
        for thread in threads:
            thread.join()

        if len(foundDirectories) == 0:
            print("\nNo directories were found.")
            return False    
        else:
            print("\nPrinting found directories:")
            for i in range(len(foundDirectories)):
                print(foundDirectories[i].url)
            return True
    except IOError as e:
        print(e)
        return False    
    except KeyboardInterrupt:
        
        if len(foundDirectories) == 0:
            print("\nSearch interrupted. No directories were found.")
            return False    
        else:
            print("\nSearch interrupted. Printing found directories:")
            for found_dir in foundDirectories:
                print(found_dir.url)
            return False    
def bruteforceFunction(url, directories,threadNumber):
    session = requests.Session()

   
    totalLines = len(directories)
    count = 0
    for directory in directories:
        count = count + 1
        percentDone = (count / totalLines) * 100
        if count % 10 == 0:
            print(colored(f"[*][Thread {threadNumber}] Progress: {round(percentDone, 2)}%", 'blue'))
        directory_url = url + "/" + directory
        response = session.get(directory_url)
        if response.status_code in [200, 301, 403, 401, 500]:
            print(colored(f"[+] Found directory: {directory_url}", 'green'))
            foundDirectories.append(dir(directory_url, response.status_code, len(response.content)))
        else:
            print(colored(f"[-] {directory_url}", 'red'))    
if __name__ == "__main__":
    main(sys.argv[1:])
