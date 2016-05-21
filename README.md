# QAD

## Output

```
[2016-05-21 12:52:57] QAD 0.1.0
[2016-05-21 12:52:57] Quick and dirty web app scanner
[2016-05-21 12:52:57] By @rascal999 - https://github.com/rascal999/
[2016-05-21 12:52:57] *******************************
[2016-05-21 12:52:57] * Target = https://www.youtube.com/
[2016-05-21 12:52:57] * IP(s) associated with target:
[2016-05-21 12:52:57] - 74.125.206.136
[2016-05-21 12:52:57] - 74.125.206.190
[2016-05-21 12:52:57] - 74.125.206.93
[2016-05-21 12:52:57] - 74.125.206.91

[2016-05-21 12:52:59] * Performing WHOIS on 74.125.206.190
[2016-05-21 12:52:59] - WHOIS name: GOOGLE
[2016-05-21 12:52:59] - WHOIS CIDR: 74.125.206.0/24
[2016-05-21 12:52:59] - More info at http://who.is/whois-ip/ip-address/74.125.206.190

[2016-05-21 12:52:59] * Checking headers
[2016-05-21 12:53:00] !!! Server header - Ytfe_Worker
[2016-05-21 12:53:00] !!! Content-Security-Policy header missing
[2016-05-21 12:53:02] !!! CONSENT set without 'Secure' flag
[2016-05-21 12:53:02] !!! CONSENT set without 'HttpOnly' flag
[2016-05-21 12:53:02] !!! PREF set without 'Secure' flag
[2016-05-21 12:53:02] !!! PREF set without 'HttpOnly' flag
[2016-05-21 12:53:02] !!! VISITOR_INFO1_LIVE set without 'Secure' flag
[2016-05-21 12:53:02] !!! YSC set without 'Secure' flag
[2016-05-21 12:53:02] !!! Public-Key-Pins header missing

[2016-05-21 12:53:02] * Checking paths
[2016-05-21 12:53:02] !!! /robots.txt found - https://www.youtube.com//robots.txt
[2016-05-21 12:53:02] !!! /crossdomain.xml found - https://www.youtube.com//crossdomain.xml
[2016-05-21 12:53:03] !!! /backup/ found - https://www.youtube.com//backup/
[2016-05-21 12:53:05] !!! /download/ found - https://www.youtube.com//download/
[2016-05-21 12:53:06] !!! /phpbb3/ found - https://www.youtube.com//phpbb3/
[2016-05-21 12:53:08] !!! /forum/ found - https://www.youtube.com//forum/
[2016-05-21 12:53:11] !!! /blog/ found - https://www.youtube.com//blog/

[2016-05-21 12:53:13] * Checking / for XSS (URL only)

[2016-05-21 12:53:13] * JavaScript URLs found
[2016-05-21 12:53:13] - https://s.ytimg.com/yts/jsbin/scheduler-vfllnPsD1/scheduler.js
[2016-05-21 12:53:13] - https://s.ytimg.com/yts/jsbin/spf-vfldNIm25/spf.js
[2016-05-21 12:53:13] - https://s.ytimg.com/yts/jsbin/www-en_US-vflkwl07t/base.js
[2016-05-21 12:53:13] - https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js
[2016-05-21 12:53:13] - https://apis.google.com/js/plusone.js
[2016-05-21 12:53:13] - https://www.youtube.com/js/cookiechoices.js
[2016-05-21 12:53:13] - https://www.blogger.com/static/v1/widgets/3107131574-widgets.js
```
