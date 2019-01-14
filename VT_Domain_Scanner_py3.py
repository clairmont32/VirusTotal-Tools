__author__ = 'Matthew Clairmont'
__version__ = '1.0'
__date__ = 'July 10, 2018'
# Remake of the Python 2.7 version
# VT Domain Scanner takes a file of domains, submits them to the Virus Total
# domain scanning API and outputs the domain and AV hits to a text file.
# If you have a private API key, you can change the sleep times to 1 for faster scanning

import time
import requests
import csv

apikey = ''  #### ENTER API KEY HERE ####

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domainErrors = []
delay = {}


# scan the domain to ensure results are fresh
def DomainScanner(domain):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

    print(domain)
    print(r)
    # sanitize domain after upload for safety
    domainSani = domain.replace('.', '[.]')
    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is not 1:
                print('There was an error submitting the domain for scanning.')
                print(jsonResponse['verbose_msg'])
            elif jsonResponse['response_code'] == -2:
                print('{!s} is queued for scanning.'.format(domainSani))
                delay[domain] = 'queued'
            else:
                print('{!s} was scanned successfully.'.format(domainSani))

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domain)

        # return domain errors for notifying user when script completes
        time.sleep(15)  ############### IF YOU HAVE A PRIVATE ACCESS YOU CAN CHANGE THIS TO 1 ###################
        return delay

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')


def DomainReportReader(domain, delay):
    # sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold,
    # you WILL get a warning email to the owner of the account if you exceed this limit.
    # Private API allows for tiered levels of queries/second.

    # check to see if we have a delay in the report being available
    # if we do, delay for a little bit longer in hopes of the report being ready
    if delay:
        if domain in delay:
            time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)
        exit(1)

    # sanitize domain after upload for safety
    domainSani = domain.replace('.', '[.]')
    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is 0:
                print('There was an error submitting the domain for scanning.')
                pass

            elif jsonResponse['response_code'] == -2:
                print('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domainSani))

            else:
                print('Report is ready for', domainSani)

            # print(jsonResponse)
            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            data = [scandate, domainSani, positives, total, permalink]
            return data

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domainSani)

        except KeyError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domainSani)

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
        time.sleep(10)
        DomainReportReader(domain, delay)

# open results file and write header
try:
    file = open('results.csv', 'w+', newline='')
    header = ['Scan Date', 'Domain', 'Detection Ratio', 'Vendor', 'Category', 'Permalink']
    headerWriter = csv.DictWriter(file, fieldnames=header)
    headerWriter.writeheader()

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)

##### CHANGE TO TEXT FILE PATH. ONE DOMAIN PER LINE! #####
try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open('domains.txt', 'r') as infile:  # keeping the file open because it shouldnt
                                              # be opened/modified during reading anyway
        for domain in infile:
            domain = domain.strip('\n')
            try:
                delay = DomainScanner(domain)
                data = DomainReportReader(domain, delay)
                with open('results.csv', 'a') as rfile:
                    dataWriter = csv.writer(rfile, delimiter = ',')
                    dataWriter.writerow(data)
                    time.sleep(15)  # wait for VT API rate limiting
            except Exception as err:  # keeping it
                print('Encountered an error but scanning will continue.', err)
                pass

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)

# inform the user if there were any errors encountered
count = len(domainErrors)
if count > 0:
    print('There were {!s} errors scanning domains'.format(count))
    print(domainErrors)
