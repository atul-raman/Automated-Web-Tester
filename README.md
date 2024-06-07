Automated Web Tester
#### Video Demo:  <https://streamable.com/dkwdzm>
#### Description: This tool uses directory fuzzing to find directories in any web server and find header vulnerabilities.
The Automated Web Tester is a Python script designed to perform a series of security checks on a given website. It utilizes the requests library to send HTTP requests and analyze the responses to check for common security headers and vulnerabilities. The script can also perform a directory brute-force attack to discover hidden directories on the web server.

Files
webtester.py: This is the main script file that contains the main function, which is the entry point of the program. It parses command-line arguments, sends HTTP requests, and performs security checks based on the responses.
Design Choices
Command-line Interface: The script uses the getopt module to parse command-line arguments. This allows users to specify the target URL and enable the brute-force mode with optional arguments (-u, -b, -h).

Security Headers: The script checks for the presence of various security headers in the HTTP response, such as HSTS, CSP, XSS-Protection, Content-Type-Options, Permitted-Cross-Domain-Policies, X-Frame-Options, Expect-CT, Feature-Policy, and Referrer-Policy. These headers help protect against common web vulnerabilities.

Directory Brute-Force: In brute-force mode, the script reads a list of directories from a specified file and tries to access them on the target server. If a directory exists, it is added to the list of found directories.

Multithreading: To improve performance, the script uses multithreading to parallelize the directory brute-force process. It creates multiple threads, each responsible for checking a subset of directories from the wordlist.

Output Formatting: The script uses the prettytable library to display the list of found directories in a formatted table. This makes it easier for the user to view and analyze the results.

Usage
To use the Automated Web Tester, run the webtester.py script with the following command-line arguments:


python webtester.py -u <url> [-b] [-h]
-u, --url: Specify the target URL.
-b, --bruteforce: Enable brute-force mode.
-h, --help: Display the help message.
Example
python webtester.py -u http://example.com -b wordlist.txt
This command will perform a security scan on http://example.com and then start a brute-force attack using the directories listed in wordlist.txt.

Conclusion
The Automated Web Tester is a versatile tool for web application security testing. It provides a simple yet effective way to identify potential vulnerabilities and improve the overall security posture of a website.

This tool is intended for educational and ethical testing purposes only. Unauthorized use of this tool against systems without explicit permission is illegal and unethical. Always obtain proper authorization before using this tool to test the security of any system.

The author is not responsible for any misuse or damage caused by this tool. Use it responsibly and in compliance with all applicable laws and regulations.
