#cypherg
#wecon.py
#finds fun things on the internet

import argparse
from BeautifulSoup import BeautifulSoup
from pprint import pprint
import requests
#import socket #uncomment this line and dns resolve block if attempting DNS PTR look ups (caution)

requests.packages.urllib3.disable_warnings()  #suppress invalid ssl cert warning

try_http = 'http://'
try_SSL = 'https://'
target_count = 0  
URI = '' #'/robots.txt' #check web server for specific URIs such as /cgi-bin, /gdorks, /vuln
http_ports = ['80','8080']   #known ports that actively refuse SSL
https_ports = ['443','8443'] #know ports that actively refuse plain HTTP

parser = argparse.ArgumentParser(description='Process IP:PORT file') 
parser.add_argument('ipfile', type=argparse.FileType('r'))
args = parser.parse_args() #reads first arg as 'ipfile' and treats it as a file 

print #print a blank line to the console for readability
for testip in args.ipfile.readlines(): #master loop. iterates through all ip:port combinations try http first then try ssl
    target_count = target_count +1
    wants_brute = False 

    if URI: #add URI to IP:PORT/URI name for specific webapp look ups
        testip = testip.strip() + URI
        print 'Searching for URI ' + URI
        
    print testip.strip() + ' <---Target #' + str(target_count)
    plain_ip = testip.split(':', 1)[0].strip() #gets ip address from ip:port
    plain_port = testip.split(':', 1)[1].strip() #gets port number from ip:port
    
    #Manually uncomment block below to enable (caution)
    ''' #super slow and lame DNS PTR look up (adds ~5/secs/ip!)
    try:
        record = socket.gethostbyaddr(plain_ip)
        print str(record)
    except socket.herror:
        pass
    '''
       
    if plain_port not in https_ports: #checks that port doesn't strictly require SSL, bypassing a timeout/refusal error
        print ':::Attempting Plain HTTP Connection:::'
        try:
            r = requests.get(try_http + testip.strip(), verify=False, allow_redirects=True, timeout=4.00)  #makes HTTP connections, gets data
            print r.url
            print 'Status code:', r.status_code
            pprint(r.headers)
            if r.history:
                print ">>Followed redirection<<"  #notifies if request was redirect from server (3XX)
            if r.status_code == 401:
                print '** Server demands authentication via 401 **'
                wants_brute = True 
            if r.text:
                try:
                    if '401' not in r.status_code and 'password' or 'login' in r.text or r.url:
                        print '** Found HTTP password form to brute :> **'
                        wants_brute = True
                    if 'web_section_id' in r.text:
                        print '** Found internal HP web_section_id **'
                    soup = BeautifulSoup(r.text)
                    print '** Extracted title: ' + soup.title.string.encode(encoding='utf-8',errors='ignore').strip() + ' **'
                    desc = soup.findAll(attrs={"name":"description"})
                    print '** Extracted Description: ' + str(desc[0]['content']).encode(encoding='utf-8',errors='ignore').strip() + ' **'
                except AttributeError:
                    pass
                except IndexError:
                    pass
                except TypeError:
                    pass
                except UnicodeEncodeError:
                    pass #from description
            if 'server' in r.headers:  #prints server name if present
                print '** Running server ' + r.headers['server'] + ' **'
            if 'etag' in r.headers:
                print '** Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
            if 'set-cookie' in r.headers:
                print '** Server sent a cookie **'
            if r.headers['www-authenticate']:
                print '** Found AUTH REALM ' + r.headers['www-authenticate'] + ' **'
                wants_brute = True
            if wants_brute is True:
                print 'Candidate for brute force attack >:D'

        except requests.exceptions.ConnectionError:
            print 'HTTP Connection to ' + str(testip).strip() + ' actively refused'
        except requests.exceptions.ReadTimeout:
            print 'HTTP Connection to ' + str(testip).strip() + ' timed out after 4.00 seconds'
        except requests.exceptions.TooManyRedirects:
            print 'Too Many Redirections'
    

    if plain_port not in http_ports: #checks that port doesn't strictly require plain HTTP, bypassing a timeout/refusal error
        print ':::Attempting SSL handshake:::'
        try:  
            r = requests.get(try_SSL + testip.strip(), verify=False, allow_redirects=True, timeout=4.00)  #makes SSL connections, gets data
            print r.url
            print 'Status code:', r.status_code
            pprint(r.headers)
            if r.history:
                print ">>Followed redirection<<"  #notifies if request was redirect from server (3XX)
            if r.status_code == 401:
                print '** Server demands authentication via 401 **'
                wants_brute = True
            if r.text:
                try:
                    if '401' not in r.status_code and 'password' or 'login' in r.text or r.url:
                        print '** Found SSL password form to brute :> **'
                        wants_brute = True
                    if 'web_section_id' in r.text:
                        print '** Found internal HP web_section_id **'
                    soup = BeautifulSoup(r.text)
                    print '** Extracted title: ' + soup.title.string.encode(encoding='utf-8',errors='ignore').strip() + ' **'
                    desc = soup.findAll(attrs={"name":"description"})
                    print '** Extracted Description: ' + str(desc[0]['content']).encode(encoding='utf-8',errors='ignore').strip() + ' **'
                except AttributeError:
                    pass
                except IndexError:
                    pass
                except TypeError:
                    pass   
                except UnicodeEncodeError:
                    pass #python 2.x sucks at unicode    
            if 'server' in r.headers:  #prints server name if present
                print '** Running server ' + r.headers['server'] + ' **'
            if 'etag' in r.headers:
                print '** Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
            if 'set-cookie' in r.headers:
                print '** Server sent a cookie **'
            if r.headers['www-authenticate']:
                print '** Found AUTH REALM ' + r.headers['www-authenticate'] + ' **'
                wants_brute = True
            if wants_brute is True:
                print'Candidate for brute force attack >:D'
            
        except requests.exceptions.ConnectionError:
            print 'SSL Connection to ' + str(testip).strip() + ' actively refused'
            print
        except requests.exceptions.ReadTimeout:
            print 'SSL Connection to ' + str(testip).strip() + ' timed out after 4.00 seconds'
            print
        except requests.exceptions.TooManyRedirects:
            print 'Too Many Redirections'
        print

    print 
    print
