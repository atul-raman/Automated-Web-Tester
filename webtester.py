import requests
import re
import sys, getopt
from termcolor import colored
import shutup; shutup.please()


def main(argv):
    url = ""
    try:
      opts, args = getopt.getopt(argv,"hu:",["url="])
    except getopt.GetoptError:
      print (colored('usage: webtester.py -u <url>','light_yellow'))
      sys.exit(2)
    for opt, arg in opts:
      if opt == '-h':
        print (colored('usage: webtester.py -u <url>','light_yellow'))
        sys.exit(1)
      elif opt in ("-u", "--url"):
        url = arg
    response = ""

    try:        
        response = requests.get(url)
    except requests.exceptions.MissingSchema:
        print(colored("Please include http:// or https:// in the url", 'light_yellow'))
        sys.exit(1)
    except requests.exceptions.InvalidURL:
        print(colored("Please provide a valid url", 'light_yellow'))

        sys.exit(1)   

    checkHSTSHeader(response)
    checkCSPHeader(response)
    checkXSSHeader(response)
    checkContentSniffing(response)


def extract_max_age(header_value):
    match = re.search(r'max-age=(\d+)', header_value)
    if match:
        return int(match.group(1))
    else:
        raise ValueError("max-age not found in the header")



def checkHSTSHeader(response):
    headers = response.headers
    if 'strict-transport-security' in response.headers:
        try:
            max_age = extract_max_age(response.headers.get('Strict-Transport-Security'))
            if(int(max_age)>=31536000):
                print(colored(f"HSTS Header is in place with valid max_age value of {max_age}",'green'))
            else:
                print(colored(f"HSTS Header is in place with invalid max_age value of {max_age}",'yellow'))

               
        except ValueError as e:
            print(colored(e,'red'))
    else:
        print(colored("HSTS Header is Not In Place",'red'))

def checkCSPHeader(response):
    headers = response.headers
    if 'content-security-policy'in headers:
        try:
            contentSecurityHeader = response.headers.get('content-security-policy')
            if("unsafe-inline" in contentSecurityHeader):
                print(colored(f"CSP Header is in place with the usage of unsafe-inline directive.",'green'))
            else:
                print(colored(f"CSP Header is in place without the usage of unsafe-inline directive.",'yellow'))
               
        except ValueError as e:
            print(colored(e,'red'))
        
    else:
        print(colored("CSP Header is Not In Place",'red'))


def checkXSSHeader(response):
    headers = response.headers
    if 'x-xss-protection'in headers:
        try:
            contentSecurityHeader = response.headers.get('x-xss-protection')
            if(contentSecurityHeader[0] == '0'):
                print(colored(f"X-XSS-Protection Header is in place but XSS filter is disabled",'yellow'))
            elif(contentSecurityHeader[0] == '1'):
                print(colored(f"X-XSS-Protection Header and XSS filter is enabled",'green'),end="")
                if('block' in contentSecurityHeader):
                    print(colored(" mode is set to block.",'green'))
                else:
                    print(colored(" mode is not set to block.",'red'))

    

                
               
        except ValueError as e:
            print(colored(e,'red'))
        
    else:
        print(colored("X-XSS-Protection Header is Not In Place",'red'))

def checkContentSniffing(response):
    headers = response.headers
    if 'x-content-type-options'in headers:
        try:
            contentTypeHeader = response.headers.get('x-content-type-options')
            if("nosniff" in contentTypeHeader):
                print(colored(f"X-Content-Type-Options header is in place set to nosniff",'green'))

            else:
                print(colored(f"X-Content-Type-Options header is in place not set to nosniff",'yellow'))


            

    

                
               
        except ValueError as e:
            colored(print(e),'red')
        
    else:
        print(colored("X-XSS-Protection Header is Not In Place",'red'))

        
    
        

if __name__ == "__main__":
    main(sys.argv[1:])