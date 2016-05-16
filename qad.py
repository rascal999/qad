#!/usr/bin/env python

import requests
import validators
import sys
import httplib2
import datetime
import socket
from urllib.parse import urlsplit
from ipwhois import IPWhois
from pprint import pprint

http_interface = httplib2.Http()
http_interface.follow_redirects = False

def timeStamp():
    now = datetime.datetime.now()
    return now.strftime("[%Y-%m-%d %H:%M:%S] ")

def checkHost(url):
    try:
        response, content = http_interface.request(url, method="GET")

        if response.status == 301 or response.status == 302:
            print(timeStamp() + "* Redirected to " + response['location'] + " ... Exiting")
            sys.exit(1)

    except httplib2.ServerNotFoundError as e:
        print (e.message) 

def checkLocation(url, path):
    urlCheck = url + path
    try:
        response, content = http_interface.request(urlCheck, method="GET")

        if response.status == 200:
            print(timeStamp() + "!!! " + path + " found - " + urlCheck)
    except httplib2.ServerNotFoundError as e:
        print (e.message) 

def checkCookies(url):
    r = requests.get(url)
    for cookie in r.cookies:
        if url.lower().find("https:",0) == 0:
            if cookie.secure == False:
                print(timeStamp() + "!!! " + cookie.name + " set without 'Secure' flag")
        if not cookie.has_nonstandard_attr('httponly') and not cookie.has_nonstandard_attr('HttpOnly'):
            print(timeStamp() + "!!! " + cookie.name + " set without 'HttpOnly' flag")

def checkHeaders(url):
    secureURL = 0
    # Determine target URL type
    if url.lower().find("https:",0) == 0:
        secureURL = 1

    print(timeStamp() + "* Checking headers")

    try:
        response, content = http_interface.request(url, method="GET")

        if 'server' in response:
            print(timeStamp() + "!!! Server header - " + response['server'])

        if 'x-powered-by' in response:
            print(timeStamp() + "!!! X-Powered-By header - " + response['x-powered-by'])

        if 'x-frame-options' not in response:
            print(timeStamp() + "!!! X-Frame-Options header missing")

        if 'content-security-policy' not in response:
            print(timeStamp() + "!!! Content-Security-Policy header missing")

        if 'x-xss-protection' not in response:
            print(timeStamp() + "!!! X-XSS-Protection header missing")

        if 'set-cookie' in response:
            checkCookies(url)

        # Check for HTTPS specific headers
        if secureURL == 1:
            if 'strict-transport-security' not in map(str.lower, response):
                print(timeStamp() + "!!! HSTS header missing")
            if 'public-key-pins' not in response:
                print(timeStamp() + "!!! Public-Key-Pins header missing")

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

def validateURL(url):
    if not validators.url(url):
        print(timeStamp() + "* Invalid URL provided")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print(sys.argv[0] + " http(s)://<target>")
        sys.exit(1)
    url = sys.argv[1]
    validateURL(url)
    domain = getDomain(url)
    intro(url, domain)
    checkHost(url)
    performWhoIs(getIPs(domain)[2][0])
    print()
    checkHeaders(url)
    print()
    print(timeStamp() + "* Checking paths")
    checkLocation(url, "/robots.txt")
    checkLocation(url, "/crossdomain.xml")
    checkLocation(url, "/sitemap.xml")
    checkLocation(url, "/admin/")
    checkLocation(url, "/backup/")
    checkLocation(url, "/upload/")
    checkLocation(url, "/download/")
    checkLocation(url, "/wp-admin/")
    checkLocation(url, "/stats/")
    checkLocation(url, "/awstats/")
    checkLocation(url, "/phpbb3/")
    checkLocation(url, "/forum/")
    checkLocation(url, "/blog/")
    print()
    checkQuickXSS(url)
    print()

if __name__ == "__main__":
    main()

# Header presence checked, what about header values?
#checkRobots
#checkHeaders
# Missing headers
# Header versions
#checkMethods
#checkThirdParty?
