#cypherg
#wecon.py
#finds fun things on the internet

import argparse
from BeautifulSoup import BeautifulSoup
from pprint import pprint
import requests
import socket 
import ssl
import OpenSSL
#-------------------------------------------------------------------------------------------------#
requests.packages.urllib3.disable_warnings()  #suppress invalid ssl cert warning
try_http = 'http://'
try_SSL = 'https://'
target_count = 0  
URI = '' #'/robots.txt' #check web server for specific URIs such as /cgi-bin, /gdorks, /vuln
http_ports = ['80','8008','8080','8088']   #known ports that actively refuse SSL
https_ports = ['443','8443'] #know ports that actively refuse plain HTTP
common_CAs = ['VeriSign','Entrust', 'www.samplexyzcorp.com']
custom_headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
#-------------------------------------------------------------------------------------------------#
parser = argparse.ArgumentParser(description='Process IP:PORT file') 
parser.add_argument('ipfile', type=argparse.FileType('r'))
args = parser.parse_args() #reads first arg as 'ipfile' and treats it as a file 
host_list = args.ipfile.readlines()
args.ipfile.close()
#-------------------------------------------------------------------------------------------------#
def makeConnection(schema, testip):
    if schema is try_http:
        print ':::Attempting Plain HTTP Connection:::'
    else:
        print ':::Attempting SSL handshake:::'
    try:
        r = requests.get(schema + testip, verify=False, allow_redirects=True, timeout=4.00, headers=custom_headers)  #makes HTTP connections, gets data   
    except requests.exceptions.ConnectionError:
        print 'Connection to ' + (schema+testip) + ' actively refused'
        return None
    except requests.exceptions.ChunkedEncodingError:
        print 'Connection to ' + (schema+testip) + ' ChunkedEncodingError'
        return None
    except requests.exceptions.ReadTimeout:
        print 'Connection to ' + (schema+testip) + ' timed out after 4.00 seconds'
        return None
    except requests.exceptions.TooManyRedirects:
        print 'Too Many Redirections'
        return None
    return r
#Done making connection

def processHeaders(r):
    global wants_brute
    wants_brute = False
    content = False
    st_code = str(r.status_code)
    print r.url + '\nStatus code: ' + st_code + '\n--Begin raw headers--'
    pprint(r.headers)
    print '--End of headers--' + '\nIntel parsed from headers:'
    if r.history:
        print "\t Followed redirection"  #notifies if request was redirect from server (3XX)
        content = True
    if 'server' in r.headers:  #prints server name if present
        print '\t Server software is ' + r.headers['server']
        content = True
    if 'x-powered-by' in r.headers:
        print '\t Server powered by ' + r.headers['x-powered-by']
        content = True
    if 'etag' in r.headers:
        print '\t Internal application etag ' + r.headers['etag']
        content = True
    if 'set-cookie' in r.headers:
        print '\t A delicious Cookie was sent '
        content = True
    if '401' in st_code:
        print '\t Server demands authentication via 401'
        wants_brute = True
    if 'www-authenticate' in r.headers:
        print '\t Found AUTH REALM ' + r.headers['www-authenticate'] 
        wants_brute = True
    if not (wants_brute or content):
        print '\t Nothing obviously useful'
    return wants_brute
#Done processing server headers

def processText(r, wants_brute):
    st_code = str(r.status_code)
    print 'Intel parsed from webpage:'
    if ('login' in r.text) or ('password' in r.text):
        print '\t Found password form to attack :>'
        wants_brute = True  
    if ('login' in r.url) or ('password' in r.url):
        print '\t Found password form to attack :>'
        wants_brute = True  
    if 'web_section_id' in r.text:
        print '\t Found internal HP web_section_id'
    return wants_brute
#Done processing plain page text

def makeSoup(r):
    soup = BeautifulSoup(r.text)
    try:
        title = soup.title.string.encode("utf-8").strip()
        print '\t Title: ' + title
        h1 = soup.h1.string.encode("utf-8").strip() 
        print '\t h1 tag: ' + h1
        find_desc = soup.findAll(attrs={"name":"description"})
        if find_desc:
            print '\t Description: ' + find_desc[0]['content']
    except AttributeError: 
        pass #could not find title or h1
    except UnicodeEncodeError:
        print '\t Description: UnicodeEncodeError'
        pass

#Done making and parsing Soup

def processCert(r):
    try:
        cert = ssl.get_server_certificate((ip, int(port)))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        # malformed cert? [Errno 10054] An existing connection was forcibly closed by the remote host
        print 'Intel gathered from certificate: '
        print '\t Subject: '
        for x in x509.get_subject().get_components():
            print '\t\t ' + x[0], x[1 ] 
        if not [ca for ca in common_CAs if ca in str(x509.get_issuer())]:
            print '\t Issuer: '
            for x in x509.get_issuer().get_components():
                print '\t\t ' + x[0], x[1]   
    except socket.error:
        print "Unable to parse certificate" 
        pass 
#Done parsing server certificate

def canAttack(wants_brute):
    if wants_brute is True: #check to see if the wants_brute bool was ever changed 
        print 'Candidate for brute force or injection attack >:D'

def dnsResolver(ip):
    try:
        record = socket.gethostbyaddr(ip)
        print str(record)
    except socket.herror:
        pass
#--------------------------------------------------------------------------------------------------#
print #print a blank line to the console for readability
for testip in host_list: #master loop. iterates through all ip:port combinations try http first then try ssl
    target_count +=1
    wants_brute = False #bool to track state of attack-ability
    testip = testip.strip()
    ip = testip.split(':', 1)[0].strip() #gets ip address from ip:port
    port = testip.split(':', 1)[1].strip() #gets port number from ip:port
    #dnsResolver(ip) #uncomment to enable DNS PTR look up *adds ~5/secs/ip!*
    if URI: #add URI to IP:PORT/URI name for specific webapp look ups
        testip = testip + URI
        print 'Searching for URI ' + URI
    print testip + ' <---Target #' + str(target_count)
#--------------------------------------------------------------------------------------------------#

    if port not in https_ports: #checks if port strictly requires http or https schema
        schema = try_http
        r = makeConnection(schema, testip)
        if r is not None:
            wants_brute = processHeaders(r) #runs processHeaders and returns a bool value to wants_brute
            wants_brute = processText(r, wants_brute) #runs processText and returns a bool value to wants_brute
            makeSoup(r)

    if port not in http_ports:
        schema = try_SSL 
        r = makeConnection(schema, testip)
        if r is not None:
            wants_brute = processHeaders(r)
            wants_brute = processText(r, wants_brute)
            makeSoup(r)
            processCert(r)

    canAttack(wants_brute)
    print '\n\n\n'
#--------------------------------------------------------------------------------------------------#