#!/usr/bin/env python

import re
import requests
import validators
import sys
import httplib2
import datetime
import socket
from urllib.parse import urlsplit, urljoin
from ipwhois import IPWhois
from pprint import pprint
from bs4 import BeautifulSoup, SoupStrainer
import pkg_resources

http_interface = httplib2.Http()
http_interface.follow_redirects = False
links = []

def timeStamp():
    now = datetime.datetime.now()
    return now.strftime("[%Y-%m-%d %H:%M:%S] ")

def checkHost(url):
    try:
        response, content = http_interface.request(url, method="GET")

        #if response.status == 301 or response.status == 302 or response.status == 303:
        if response.status == 301 or response.status == 302:
            print(timeStamp() + "* Redirected to " + response['location'] + " ... Exiting")
            sys.exit(1)
    except httplib2.ServerNotFoundError as e:
        print (e.message)

    http_interface.follow_redirects = True

def addLink(url):
    if url not in links:
        links.append(url)

def checkLinks(url):
    try:
        status, response = http_interface.request(url)

        for link in BeautifulSoup(response, "html.parser", parse_only=SoupStrainer("a")):
            if link.has_attr('href'):
                addLink(urljoin(url,link['href']))
        for link in BeautifulSoup(response, "html.parser", parse_only=SoupStrainer("script")):
            if link.has_attr('src'):
                addLink(urljoin(url,link['src']))
    except:
        return

def checkLocation(url, path):
    urlCheck = url + path
    try:
        response, content = http_interface.request(urlCheck, method="GET")

        if response.status == 200:
            print(timeStamp() + "!!! " + path + " found - " + urlCheck)
            # Checks for stuff like pasword input on HTTP page
            checkForm(url + path)
            checkLinks(url + path)
    except httplib2.ServerNotFoundError as e:
        print(e.message) 

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

    print()
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
        print()
        print(timeStamp() + "* Checking / for XSS (URL only)")
        try:
            response, content = http_interface.request(url_xss, method="GET")
        except httplib2.HttpLib2Error as e:
            print(timeStamp() + "[ERROR] " + str(e))
            print(timeStamp() + "[ERROR] QAD will try and deal with this at some point..")
            sys.exit(1)

        if b"<>qadqad" in content:
            print(timeStamp() + "!!! Reflected XSS potential at " + url_xss)
    except httplib2.ServerNotFoundError as e:
        print(e.message)

def getDomain(url):
    domain = "{0.netloc}".format(urlsplit(url))
    return domain

def performWhoIs(IP):
    print()
    print(timeStamp() + "* Performing WHOIS on " + IP)
    obj = IPWhois(IP)
    res = obj.lookup_whois()
    print(timeStamp() + "- WHOIS name: " + res["nets"][0]['name'])
    print(timeStamp() + "- WHOIS CIDR: " + res['asn_cidr'])
    print(timeStamp() + "- More info at http://who.is/whois-ip/ip-address/" + IP)

def intro(url, domain):
    print(timeStamp() + "QAD " + pkg_resources.get_distribution('QAD').version)
    print(timeStamp() + "Quick and dirty web app scanner")
    print(timeStamp() + "By @rascal999 - https://github.com/rascal999/")
    print(timeStamp() + "*******************************")
    print(timeStamp() + "* Target = " + url)
    print(timeStamp() + "* IP(s) associated with target:")
    IPs = getIPs(domain)
    for IP in IPs[2]:
        print(timeStamp() + "- " + IP)

def validateURL(url):
    if not validators.url(url):
        print(timeStamp() + "* Invalid URL provided")
        sys.exit(1)

def checkForm(url):
    from bs4 import BeautifulSoup

    try:
        response, content = http_interface.request(url, method="GET")
    except httplib2.ServerNotFoundError as e:
        print (e.message)
        sys.exit(1)

    if url.lower().find("https:",0) != 0:
        parsed_html = BeautifulSoup(content, "html.parser")
        try:
            if len(parsed_html.body.find_all('input', attrs={'type':'password'})) > 0:
                print(timeStamp() + "!!! Possible login/registration form over HTTP connection at " + response['content-location'])
        except:
            return

def checkJS():
    print()
    print(timeStamp() + "* JavaScript URLs found")
    for link in links:
        if re.search(".js$",link):
            print(timeStamp() + "- " + link)

def main():
    if len(sys.argv) != 2:
        print(sys.argv[0] + " http(s)://<target>")
        sys.exit(1)
    url = sys.argv[1]
    validateURL(url)

    protocol = url.split('://')[0]
    domain = getDomain(url)
    domain_only = protocol + "://" + domain + "/"
    # Hello
    intro(url, domain)
    # Check for 301 and 302 (not 303)
    checkHost(url)
    # Perform WHOIS
    performWhoIs(getIPs(domain)[2][0])
    # Header checks (yay!)
    checkHeaders(url)

    # File checks
    # TODO What if user sets URL to http://donkey.dick/some-shit/ ?
    # Need http://domain/ extraction
    print()
    print(timeStamp() + "* Checking paths")
    checkLocation(domain_only, "/robots.txt")
    checkLocation(domain_only, "/crossdomain.xml")
    checkLocation(domain_only, "/sitemap.xml")
    checkLocation(domain_only, "/admin/")
    checkLocation(domain_only, "/backup/")
    checkLocation(domain_only, "/upload/")
    checkLocation(domain_only, "/download/")
    checkLocation(domain_only, "/wp-admin/")
    #checkLocation(domain_only, "/stats/")
    checkLocation(domain_only, "/awstats/")
    checkLocation(domain_only, "/phpbb3/")
    checkLocation(domain_only, "/forum/")
    checkLocation(domain_only, "/login/")
    checkLocation(domain_only, "/blog/")

    # Proper Noddy(tm) XSS checks
    checkQuickXSS(url)

    # List JS files
    checkJS()

    # Crawler (not threaded, could get caught in infinite loop)
    #for link in links:
    #    checkLinks(link)

if __name__ == "__main__":
    main()

# Header presence checked, what about header values?
#checkHeaders
# Missing headers
# Header versions
#checkMethods
