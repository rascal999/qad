# QAD

## Output

``./qad.py http://10fastfingers.com/login
[2016-05-17 23:43:14] QAD v0.1
[2016-05-17 23:43:14] Quick and dirty web app scanner
[2016-05-17 23:43:14] By @rascal999 - https://github.com/rascal999/
[2016-05-17 23:43:14] *******************************
[2016-05-17 23:43:14] * Target = http://10fastfingers.com/login
[2016-05-17 23:43:14] * IP(s) associated with target:
[2016-05-17 23:43:14] - 85.13.148.32

[2016-05-17 23:43:15] * Performing WHOIS on 85.13.148.32
[2016-05-17 23:43:15] - WHOIS name: NMM-NET-1
[2016-05-17 23:43:15] - WHOIS CIDR: 85.13.148.0/24
[2016-05-17 23:43:15] - More info at http://who.is/whois-ip/ip-address/85.13.148.32

[2016-05-17 23:43:15] * Checking headers
[2016-05-17 23:43:15] !!! Server header - Apache
[2016-05-17 23:43:15] !!! X-Frame-Options header missing
[2016-05-17 23:43:15] !!! Content-Security-Policy header missing
[2016-05-17 23:43:15] !!! X-XSS-Protection header missing
[2016-05-17 23:43:15] !!! CakeCookie[lang] set without 'HttpOnly' flag

[2016-05-17 23:43:15] * Checking paths
[2016-05-17 23:43:15] !!! /robots.txt found - http://10fastfingers.com//robots.txt
[2016-05-17 23:43:15] !!! /crossdomain.xml found - http://10fastfingers.com//crossdomain.xml
[2016-05-17 23:43:16] !!! /admin/ found - http://10fastfingers.com//admin/
[2016-05-17 23:44:21] !!! /stats/ found - http://10fastfingers.com//stats/
[2016-05-17 23:44:22] !!! /forum/ found - http://10fastfingers.com//forum/
[2016-05-17 23:44:23] !!! /blog/ found - http://10fastfingers.com//blog/

[2016-05-17 23:44:23] * Checking / for XSS (URL only)

[2016-05-17 23:44:23] * Checking HTML form code
[2016-05-17 23:44:23] !!! Possible login/registration form over HTTP connection at http://10fastfingers.com/login``
