#cypherg
#wecon.py
#finds fun things on the internet

import argparse
from BeautifulSoup import BeautifulSoup
from pprint import pprint
import re
import requests

requests.packages.urllib3.disable_warnings()  #suppress invalid ssl cert warning

try_http = 'http://'
try_SSL = 'https://'
target_count = 0  
URI = '' #'/robots.txt' #check web server for specific URIs such as /cgi-bin, /gdorks, /vuln

parser = argparse.ArgumentParser(description='Process IP:PORT file') 
parser.add_argument('ipfile', type=argparse.FileType('r'))
args = parser.parse_args() #reads first arg as 'ipfile' and treats it as a file 

print #print a blank line to the console for readability
for testip in args.ipfile.readlines(): #master loop. iterates through all ip:port combinations try http first then try ssl
    target_count = target_count +1
    if URI:
        testip = testip.rstrip() + URI
        print 'Searching for URI ' + URI
        
    print testip.rstrip() + ' <---Target #' + str(target_count)
    try:
        r = requests.get(try_http + testip.rstrip(), verify=False, allow_redirects=True, timeout=5.00)  #makes HTTP connections, gets data
        print r.url
        print 'Status code:', r.status_code
        pprint(r.headers)
        if r.history:
            print ">>Followed redirection<<"  #notifies if request was redirect from server (3XX)
        if r.status_code == 401:
            print '** Found BASIC AUTH to brute :> **'
        if r.text:
            try:
             soup = BeautifulSoup(r.text)
             print '** Extracted title: ' + soup.title.string + ' **'
             desc = soup.findAll(attrs={"name":"description"})
             print '** Extracted Description: ' + desc[0]['content']
             password = re.search('password*', r.text)
             print '** Found password form to brute :> **'
            except AttributeError:
                pass
            except IndexError:
                pass
        if 'server' in r.headers:  #prints server name if present
            print '** Running server ' + r.headers['server'] + ' **'
        if 'etag' in r.headers:
            print '** HP Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
        if 'set-cookie' in r.headers:
            print '** Server sent a cookie **'
        if 'www-authenticate' in r.headers:
            print '** Found REALM ' + r.headers['www-authenticate']
    except requests.exceptions.ConnectionError:
        print 'HTTP Connection to ' + str(testip).rstrip() + ' actively refused'
    except requests.exceptions.ReadTimeout:
        print 'HTTP Connection to ' + str(testip) + ' timed out'
    print ':::Attempting SSL handshake:::'

    try:
        r = requests.get(try_SSL + testip.rstrip(), verify=False, allow_redirects=True, timeout=5.00)  #makes SSL connections, gets data
        print r.url
        print 'Status code:', r.status_code
        pprint(r.headers)
        if r.history:
            print ">>Followed redirection<<"  #notifies if request was redirect from server (3XX)
        if r.status_code == 401:
            print '** Found BASIC AUTH to brute :> **'
        if r.text:
            try:
                soup = BeautifulSoup(r.text)
                print '** Extracted title: ' + soup.title.string + ' **'
                desc = soup.findAll(attrs={"name":"description"})
                print '** Extracted Description: ' + desc[0]['content']
                password = re.search('password*', r.text)
                print '** Found password form to brute :> **'
            except AttributeError:
                pass
            except IndexError:
                pass
        if 'server' in r.headers:  #prints server name if present
            print '** Running server ' + r.headers['server'] + ' **'
        if 'etag' in r.headers:
            print '** HP Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
        if 'set-cookie' in r.headers:
            print '** Server sent a cookie **'
        if 'www-authenticate' in r.headers:
            print '** Found REALM ' + r.headers['www-authenticate']
        print
    except requests.exceptions.ConnectionError:
        print 'SSL Connection to ' + str(testip).rstrip() + ' actively refused'
        print
    except requests.exceptions.ReadTimeout:
        print 'SSL Connection to ' + str(testip).rstrip() + ' timed out'
        print
    print
    print 
