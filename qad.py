#!/usr/bin/env python

import sys
import httplib2
import datetime
import socket
from urllib.parse import urlsplit
from ipwhois import IPWhois

http_interface = httplib2.Http()

def timeStamp():
    now = datetime.datetime.now()
    return now.strftime("[%Y-%m-%d %H:%M:%S] ")

def checkProtocol(url):
    secureURL = 0
    # Determine target URL type
    if url.lower().find("https:",0) == 0:
        secureURL = 1
        print(timeStamp() + "* HTTPS URL provided, checking for HTTP on TCP port 80")
    else:
        print(timeStamp() + "* HTTP URL provided, checking for HTTPS on TCP port 443")
    # If no SSL, try SSL connection on TCP port 443
    # If SSL, try plaintext port 80 connection and check for HSTS/30x

def checkRobots(url):
    url_robots = url + "/robots.txt"
    try:
        print(timeStamp() + "* Checking /robots.txt ... ",end="")
        response, content = http_interface.request(url_robots, method="GET")
        print(response.status)

        if response.status == 200:
            print(timeStamp() + "!!! robots.txt found - " + url + "/robots.txt")
    except httplib2.ServerNotFoundError as e:
        print (e.message) 

def checkHeaders(url):
    secureURL = 0
    # Determine target URL type
    if url.lower().find("https:",0) == 0:
        secureURL = 1

    print(timeStamp() + "* Checking headers")

    try:
        response, content = http_interface.request(url, method="GET")

        #print(timeStamp() + "Header list:")
        #for header in response:
        #    print(timeStamp() + "- " + header)

        if 'x-frame-options' not in map(str.lower, response):
            print(timeStamp() + "!!! X-Frame-Options header missing")

        if 'content-security-policy' not in map(str.lower, response):
            print(timeStamp() + "!!! Content-Security-Policy header missing")

        if 'x-xss-protection' not in map(str.lower, response):
            print(timeStamp() + "!!! X-XSS-Protection header missing")

        # Check for HTTPS specific headers
        if secureURL == 1:
            if 'strict-transport-security' not in map(str.lower, response):
                print(timeStamp() + "!!! HSTS header missing")

    except httplib2.ServerNotFoundError as e:
        print (e.message)

def getIPs(domain):
        try:
            ips = socket.gethostbyname_ex(domain)
        except socket.gaierror:
            ips=[]
            print(timeStamp() + "Cannot resolve " + domain)
            sys.exit(1)
        return ips

def checkQuickXSS(url):
    url_xss = url + "/%3c%3eqadqad"

    try:
        print(timeStamp() + "* Checking / for XSS (URL only)")
        response, content = http_interface.request(url_xss, method="GET")

        if b"<>qadqad" in content:
            print(timeStamp() + "!!! Reflected XSS potential at " + url_xss)
    except httplib2.ServerNotFoundError as e:
        print (e.message)

def getDomain(url):
    domain = "{0.netloc}".format(urlsplit(url))
    return domain

def performWhoIs(IP):
    print(timeStamp() + "* Performing WHOIS on " + IP)
    obj = IPWhois(IP)
    res = obj.lookup_whois()
    print(timeStamp() + "- WHOIS name: " + res["nets"][0]['name'])
    print(timeStamp() + "- WHOIS CIDR: " + res['asn_cidr'])
    print(timeStamp() + "- More info at http://who.is/whois-ip/ip-address/" + IP)

def intro(url, domain):
    print(timeStamp() + "QAD v0.1")
    print(timeStamp() + "Quick and dirty web app scanner")
    print(timeStamp() + "By @rascal999 - https://github.com/rascal999/")
    print(timeStamp() + "*******************************")
    print(timeStamp() + "* Target = " + url)
    print(timeStamp() + "* IP(s) associated with target:")
    IPs = getIPs(domain)
    for IP in IPs[2]:
        print(timeStamp() + "- " + IP)
    print()

def main():
    if len(sys.argv) != 2:
        print(sys.argv[0] + " http(s)://<target>")
        sys.exit(1)
    url = sys.argv[1]
    domain = getDomain(url)
    intro(url, domain)
    performWhoIs(getIPs(domain)[2][0])
    print()
    checkHeaders(url)
    print()
    checkRobots(url)
    print()
    checkQuickXSS(url)
    print()

if __name__ == "__main__":
    main()

#checkRobots
#checkHeaders
# Missing headers
# Header versions
#checkMethods
#checkThirdParty?
