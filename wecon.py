#cypherg
#wecon.py
#finds fun things on the internet


#import lxml
from pprint import pprint
import requests

requests.packages.urllib3.disable_warnings() #suppress invalid ssl cert warning

try_http = 'http://'   
try_SSL = 'https://' #testips will be an imported file
testips = ['X:10000','X:80','X:80','X:8444','X:80']


for testip in testips: #master loop. iterates through all ip:port combinations. try http first then try ssl
	try:
		r = requests.get(try_http+testip, verify=False, allow_redirects=True, timeout=5.00) #makes HTTP connections, gets data
		print r.url, 'Response:', r.status_code #prints data
		if  r.history:
			pprint('Followed redirection') #notifies if request was redirect from server (302)
		pprint(r.headers)
		if 'server' in r.headers: #prints server name if present
			print '** Running server ' + r.headers['server'] + ' **'
	except requests.exceptions.ConnectionError: #catches servers refusing to communicate
		pprint('HTTP Connection to ' + str(testip) + ' actively refused')
	except requests.exceptions.ReadTimeout: #catches servers too slow to communicate
		pprint('HTTP Connection to ' + str(testip) + ' timed out')

	try:
		r = requests.get(try_SSL+testip, verify=False, allow_redirects=True, timeout=5.00) #makes SSL connections, gets data
		print r.url, 'Response:', r.status_code #prints data
		if  r.history:
			pprint('Followed redirection')	#notifies if request was redirect from server (302)
		pprint(r.headers)	
		if 'server' in r.headers: #prints server name if present
			print '** Running server ' + r.headers['server'] + ' **'
		print
	except requests.exceptions.ConnectionError:
		pprint('SSL Connection to ' + str(testip) + ' actively refused')
		print
	except requests.exceptions.ReadTimeout:
		pprint('SSL Connection to ' + str(testip) + ' timed out')
		print
	continue #continue to iterate through IPs even if there's an exception
exit()