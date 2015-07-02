__author__ = 'Matthew Clairmont'
__email__ = 'matthew.clairmont1@gmail.com'
__version__ = '1.0'
__date__ = '07/01/2015'
#Designed for Python 2.7, this is the initial creation of this script with no error checking. Any errors may be related to incorrect API key, or bad domain formatting in input file. Updates will be provided in intervals over the next few months. 
#VT Domain Scanner takes a file of domains, submits them to the Virus Total domain scanning API and outputs the domain and AV hits to a text file.

import urllib
import urllib2
import time
import json as simplejson

#submits domain to VT to generate a fresh report for DomainReportReader()
def DomainScanner(domain):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'

    parameters = {'url': domain,
                  'apikey': '<ENTER YOUR API KEY HERE!!!!>'}

    #URL encoding and submission
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    print('Domain scanned successfully ')

    #for URL scan report debugging only
    #print(response)  

def DomainReportReader(domain):
    #sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold, you WILL get a warning email to the owner of the account if you exceed this limit. Private API allows for tiered levels of queries/second.
    time.sleep(15)

    #this is the VT url scan api link
    url = 'https://www.virustotal.com/vtapi/v2/url/report'

    #API parameters
    parameters = {'resource': domain,
                  'apikey': '<ENTER YOUR API KEY HERE!!!!>'}

    #URL encoding and submission
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()

    """"response harvesting in json dictionary form. See sample response --> {'permalink': 'https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1435364830/', 'resource': 'http://www.google.com', 'url': 'http://www.google.com/', 'response_code': 1, 'scan_date': '2015-06-27 00:27:10', 'scan_id': 'dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1435364830', 'verbose_msg': 'Scan finished, scan information embedded in this object', 'filescan_id': null, 'positives': 0, 'total': 63, 'scans': {'CLEAN MX': {'detected': false, 'result': 'clean site'}, 'VX Vault': {'detected': false, 'result': 'clean site'}, 'ZDB Zeus': {'detected': false, 'result': 'clean site'}, 'Tencent': {'detected': false, 'result': 'clean site'}, 'MalwarePatrol': {'detected': false, 'result': 'clean site'}, 'ZCloudsec': {'detected': false, 'result': 'clean site'}, 'PhishLabs': {'detected': false, 'result': 'unrated site'}, 'Zerofox': {'detected': false, 'result': 'clean site'}, 'K7AntiVirus': {'detected': false, 'result': 'clean site'}, 'Quttera': {'detected': false, 'result': 'suspicious site'}, 'Spam404': {'detected': false, 'result': 'clean site'}, 'AegisLab WebGuard': {'detected': false, 'result': 'clean site'}, 'MalwareDomainList': {'detected': false, 'result': 'clean site', 'detail': 'http://www.malwaredomainlist.com/mdl.php?search=www.google.com'}, 'ZeusTracker': {'detected': false, 'result': 'clean site', 'detail': 'https://zeustracker.abuse.ch/monitor.php?host=www.google.com'}, 'zvelo': {'detected': false, 'result': 'clean site'}, 'Google Safebrowsing': {'detected': false, 'result': 'clean site'}, 'Kaspersky': {'detected': false, 'result': 'clean site'}, 'BitDefender': {'detected': false, 'result': 'clean site'}, 'Dr.Web': {'detected': false, 'result': 'clean site'}, 'ADMINUSLabs': {'detected': false, 'result': 'clean site'}, 'C-SIRT': {'detected': false, 'result': 'clean site'}, 'CyberCrime': {'detected': false, 'result': 'clean site'}, 'Websense ThreatSeeker': {'detected': false, 'result': 'clean site'}, 'CRDF': {'detected': false, 'result': 'clean site'}, 'Webutation': {'detected': false, 'result': 'clean site'}, 'Trustwave': {'detected': false, 'result': 'clean site'}, 'Web Security Guard': {'detected': false, 'result': 'clean site'}, 'G-Data': {'detected': false, 'result': 'clean site'}, 'Malwarebytes hpHosts': {'detected': false, 'result': 'clean site'}, 'Wepawet': {'detected': false, 'result': 'clean site'}, 'AlienVault': {'detected': false, 'result': 'clean site'}, 'Emsisoft': {'detected': false, 'result': 'clean site'}, 'Malc0de Database': {'detected': false, 'result': 'clean site', 'detail': 'http://malc0de.com/database/index.php?search=www.google.com'}, 'SpyEyeTracker': {'detected': false, 'result': 'clean site', 'detail': 'https://spyeyetracker.abuse.ch/monitor.php?host=www.google.com'}, 'malwares.com URL checker': {'detected': false, 'result': 'clean site'}, 'Phishtank': {'detected': false, 'result': 'clean site'}, 'Malwared': {'detected': false, 'result': 'clean site'}, 'Avira': {'detected': false, 'result': 'clean site'}, 'OpenPhish': {'detected': false, 'result': 'clean site'}, 'Antiy-AVL': {'detected': false, 'result': 'clean site'}, 'SCUMWARE.org': {'detected': false, 'result': 'clean site'}, 'FraudSense': {'detected': false, 'result': 'clean site'}, 'Opera': {'detected': false, 'result': 'clean site'}, 'Comodo Site Inspector': {'detected': false, 'result': 'clean site'}, 'Malekal': {'detected': false, 'result': 'clean site'}, 'ESET': {'detected': false, 'result': 'clean site'}, 'Sophos': {'detected': false, 'result': 'unrated site'}, 'Yandex Safebrowsing': {'detected': false, 'result': 'clean site', 'detail': 'http://yandex.com/infected?l10n=en&url=http://www.google.com/'}, 'SecureBrain': {'detected': false, 'result': 'clean site'}, 'Malware Domain Blocklist': {'detected': false, 'result': 'clean site'}, 'Blueliv': {'detected': false, 'result': 'clean site'}, 'Netcraft': {'detected': false, 'result': 'unrated site'}, 'PalevoTracker': {'detected': false, 'result': 'clean site'}, 'AutoShun': {'detected': false, 'result': 'unrated site'}, 'ThreatHive': {'detected': false, 'result': 'clean site'}, 'ParetoLogic': {'detected': false, 'result': 'clean site'}, 'Rising': {'detected': false, 'result': 'clean site'}, 'URLQuery': {'detected': false, 'result': 'unrated site'}, 'StopBadware': {'detected': false, 'result': 'unrated site'}, 'Sucuri SiteCheck': {'detected': false, 'result': 'clean site'}, 'Fortinet': {'detected': false, 'result': 'clean site'}, 'ZeroCERT': {'detected': false, 'result': 'clean site'}, 'Baidu-International': {'detected': false, 'result': 'clean site'}}}"""

	#stores json response to variable for calling specific sections in the next block of code
    response_dict = simplejson.loads(json)

    #pull critical snippets from report and convert to strings for output formatting
    permalink = response_dict.get('permalink', {})
    scanDate = response_dict.get('scan_date', {})
    avHit = response_dict.get('positives', {})
    total = response_dict.get('total', {})
	
	#convert numbers to string for output formatting
    avHit = str(avHit)
    total = str(total)
    ratio = avHit + '/' + total

    #format results and write to screen and results.txt
    resultsString = (domain + ' was scanned on ' + scanDate + ' and contained a ' + ratio + ' AV detection ratio. See full report in results file for further information')
    print(resultsString)
    resultsOutput = domain + ',' + ratio + ',' + permalink + '\n'
    print('Writing to results.txt\n')
    results.write(resultsOutput)

#input/output files. Domains should NOT be obfuscated!!! Can accept HTTP, www., or straight domain
badDomains = open('/home/username/Desktop/domains.txt', 'r') ###### change path for input file
results = open('/home/username/Desktop/results.txt', 'w') ###### change path for input file
results.write('') #clear any current data in output file

#iterate through domain input file and pass 'domain' to functions
for line in badDomains:
    domain = line.rstrip('\n')
    print('Passing ' + domain + ' to VirusTotal\n')
    DomainScanner(domain)
    DomainReportReader(domain)
