#cypherg
#wecon.py
#finds fun things on the internet

import argparse
from BeautifulSoup import BeautifulSoup
from pprint import pprint
import requests
import socket #uncomment this line and dns resolve block if attempting DNS PTR look ups (caution)
import ssl
import OpenSSL

requests.packages.urllib3.disable_warnings()  #suppress invalid ssl cert warning

try_http = 'http://'
try_SSL = 'https://'
target_count = 0  
URI = '' #'/robots.txt' #check web server for specific URIs such as /cgi-bin, /gdorks, /vuln
http_ports = ['80','8008','8080','8088']   #known ports that actively refuse SSL
https_ports = ['443','8443'] #know ports that actively refuse plain HTTP
common_CAs = ['VeriSign','Entrust', 'samplexyzcorp']
custom_headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}

parser = argparse.ArgumentParser(description='Process IP:PORT file') 
parser.add_argument('ipfile', type=argparse.FileType('r'))
args = parser.parse_args() #reads first arg as 'ipfile' and treats it as a file 

print #print a blank line to the console for readability
for testip in args.ipfile.readlines(): #master loop. iterates through all ip:port combinations try http first then try ssl
    testip = testip.strip()
    ip = testip.split(':', 1)[0].strip() #gets ip address from ip:port
    port = testip.split(':', 1)[1].strip() #gets port number from ip:port
    target_count +=1
    wants_brute = False
    ''' #super slow and lame DNS PTR look up (adds ~5/secs/ip!)
    try:
        record = socket.gethostbyaddr(plain_ip)
        print str(record)
    except socket.herror:
        pass
    '''
    if URI: #add URI to IP:PORT/URI name for specific webapp look ups
        testip = testip.strip() + URI
        print 'Searching for URI ' + URI




















        
    print testip + ' <---Target #' + str(target_count)

   
    if port not in https_ports: #checks if port strictly requires https
        print ':::Attempting Plain HTTP Connection:::'
        try:
            r = requests.get(try_http + testip, verify=False, allow_redirects=True, timeout=4.00)  #makes HTTP connections, gets data
            print r.url + '\nStatus code: ' + str(r.status_code)
            print '--Begin raw headers--'
            pprint(r.headers)
            print '--End of headers--'
            print 'Intel parsed from headers:'
            if r.history:
                print "\t Followed redirection"  #notifies if request was redirect from server (3XX)
            if 'server' in r.headers:  #prints server name if present
                print '\t Server software is ' + r.headers['server'] 
            if 'etag' in r.headers:
                print '\t Internal Application - Found etag in headers ' + r.headers['etag']
            if 'set-cookie' in r.headers:
                print '\t A delicious Cookie was sent '
            if r.status_code == '401':
                print '\t Server demands authentication via 401'
                wants_brute = True
            if 'www-authenticate' in r.headers:
                print '\t Found AUTH REALM ' + r.headers['www-authenticate'] 
                wants_brute = True



            if r.text:
                print 'Intel parsed from webpage:'
            if '401' not in str(r.status_code):
                if 'password' or 'login' in r.text or r.url:
                    print '\t Found SSL password form to brute :>'
                    wants_brute = True
            if 'web_section_id' in r.text:
                    print '\t Found internal HP web_section_id'
            soup = BeautifulSoup(r.text)
            try:
                title = soup.title.string.encode("utf-8")
                print '\t Title: ' + title
                h1 = soup.h1.string 
                print '\t h1 tag ' + h1
            except AttributeError: 
                pass #could not find title or h1
            find_desc = soup.findAll(attrs={"name":"description"})
            if find_desc:
                desc = str(find_desc[0]['content'])
                print '\t Description: ' + desc 
            if wants_brute is True:
                print 'Candidate for brute force attack >:D'
            #Done processing page text


        except requests.exceptions.ConnectionError:
            print 'HTTP Connection to ' + str(testip).strip() + ' actively refused'
        except requests.exceptions.ReadTimeout:
            print 'HTTP Connection to ' + str(testip).strip() + ' timed out after 4.00 seconds'
        except requests.exceptions.TooManyRedirects:
            print 'Too Many Redirections'
        #Done handling connection exceptions


    

    if port not in http_ports: #checks that port doesn't strictly require plain HTTP, bypassing a timeout/refusal error
        print ':::Attempting SSL handshake:::'
        addy = try_SSL + testip
        try:  
            r = requests.get(addy, headers=custom_headers, verify=False, allow_redirects=True, timeout=4.00)  #makes SSL connections
            print r.url + '\nStatus code: ' + str(r.status_code)
            print '--Begin raw headers--'
            pprint(r.headers)
            print '--End of headers--'
            print 'Intel parsed from headers:'
            if r.history:
                print "\t Followed redirection"  #notifies if request was redirect from server (3XX)
            if 'server' in r.headers:  #prints server name if present
                print '\t Server software is ' + r.headers['server'] 
            if 'etag' in r.headers:
                print '\t Internal Application - Found etag in headers ' + r.headers['etag']
            if 'set-cookie' in r.headers:
                print '\t A delicious Cookie was sent '
            if r.status_code == '401':
                print '\t Server demands authentication via 401'
                wants_brute = True
            if 'www-authenticate' in r.headers:
                print '\t Found AUTH REALM ' + r.headers['www-authenticate'] 
                wants_brute = True
            #Done processing server headers
            
            if r.text:
                print 'Intel parsed from webpage:'
            if '401' not in str(r.status_code):
                if 'password' or 'login' in r.text or r.url:
                    print '\t Found SSL password form to brute :>'
                    wants_brute = True
            if 'web_section_id' in r.text:
                    print '\t Found internal HP web_section_id'
            soup = BeautifulSoup(r.text)
            try:
                title = soup.title.string.encode("utf-8")
                print '\t Title: ' + title
                h1 = soup.h1.string 
                print '\t h1 tag ' + h1
            except AttributeError: 
                pass #could not find title or h1
            find_desc = soup.findAll(attrs={"name":"description"})
            if find_desc:
                desc = str(find_desc[0]['content'])
                print '\t Description: ' + desc 
            if wants_brute is True:
                print 'Candidate for brute force attack >:D'
            #Done processing page text


        except requests.exceptions.ConnectionError:
            print 'SSL Connection to ' + testip + ' actively refused\n\n\n'
            continue
        except requests.exceptions.ReadTimeout:
            print 'SSL Connection to ' + testip + ' timed out after 4.00 seconds\n\n\n'
            continue
        except requests.exceptions.TooManyRedirects:
            print 'Too Many Redirections\n\n\n'
            continue
        #Done handling connection exceptions

        
 





        print 'Intel gathered from certificate: '            
        try:
            cert = ssl.get_server_certificate((ip, int(port)))
        except socket.error:
            print "\t Shucks, couldn't parse cert\n\n\n" 
            continue
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
         # malformed cert? [Errno 10054] An existing connection was forcibly closed by the remote host
        print '\t Subject: '
        for x in x509.get_subject().get_components():
            print '\t\t ' + x[0], x[1 ] 
        if 'VeriSign' not in str(x509.get_issuer()):
            if 'www.samplexyzcorp.com' not in str(x509.get_issuer()):
                if 'Entrust' not in str(x509.get_issuer()):
                    print '\t Issuer: '
                    for x in x509.get_issuer().get_components():
                        print '\t\t ' + x[0], x[1]         
    print 
    print
