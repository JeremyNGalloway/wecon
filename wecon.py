#cypherg
#wecon.py
#finds fun things on the internet


from pprint import pprint
import requests
from BeautifulSoup import BeautifulSoup

requests.packages.urllib3.disable_warnings()  #suppress invalid ssl cert warning

try_http = 'http://'
try_SSL = 'https://'  #testips will be an imported file
testips = ['X:10000', 'X:80', 'X:80', 'X:8444', 'X:80']

for testip in testips:  #master loop. iterates through all ip:port combinations. try http first then try ssl
	try:
		r = requests.get(try_http + testip, verify=False, allow_redirects=True,
		                 timeout=5.00)  #makes HTTP connections, gets data
		print r.url, 'Response:', r.status_code  #prints data
		if r.history:
			pprint('Followed redirection')  #notifies if request was redirect from server (302)
		pprint(r.headers)
		if r.text:
			try:
				soup = BeautifulSoup(r.text)
				print '** Extracted title: ' + soup.title.string + ' **'
				desc = soup.findAll(attrs={"name":"description"})
				print '** Extracted Description: ' + desc[0]['content']
				login = soup.findAll(attrs={"name":"login"})
				print '** Found login form to brute :> **'
			except AttributeError:
				pass
			except IndexError:
				pass
		if 'server' in r.headers:  #prints server name if present
			print '** Running server ' + r.headers['server'] + ' **'
		if 'etag' in r.headers:
			print '** HP Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
		if 'set-cookie' in r.headers:
			print '** Server sent cookie ' + r.headers['set-cookie'] + ' **'
	except requests.exceptions.ConnectionError:  #catches servers refusing to communicate
		pprint('HTTP Connection to ' + str(testip) + ' actively refused')
	except requests.exceptions.ReadTimeout:  #catches servers too slow to communicate
		pprint('HTTP Connection to ' + str(testip) + ' timed out')

	try:
		r = requests.get(try_SSL + testip, verify=False, allow_redirects=True,
		                 timeout=5.00)  #makes SSL connections, gets data
		print r.url, 'Response:', r.status_code  #prints data
		if r.history:
			pprint('Followed redirection')  #notifies if request was redirect from server (302)
		pprint(r.headers)
		if r.text:
			try:
				soup = BeautifulSoup(r.text)
				print '** Extracted title: ' + soup.title.string + ' **'
				desc = soup.findAll(attrs={"name":"description"})
				print '** Extracted Description: ' + desc[0]['content']
				login = soup.findAll(attrs={"name":"login"})
				print '** Found login form to brute :> **'
			except AttributeError:
				pass
			except IndexError:
				pass
		if 'server' in r.headers:  #prints server name if present
			print '** Running server ' + r.headers['server'] + ' **'
		if 'etag' in r.headers:
			print '** HP Internal Application - Found etag in headers ' + r.headers['etag'] + ' **'
		if 'set-cookie' in r.headers:
			print '** Server sent cookie ' + r.headers['set-cookie'] + ' **'
		print
	except requests.exceptions.ConnectionError:
		pprint('SSL Connection to ' + str(testip) + ' actively refused')
		print
	except requests.exceptions.ReadTimeout:
		pprint('SSL Connection to ' + str(testip) + ' timed out')
		print

