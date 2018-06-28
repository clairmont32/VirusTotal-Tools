__author__ = 'Matthew Clairmont'
__version__ = '1.0'
__date__ = 'Jun 27, 2018'
# Remake of the Python 2.7 version
# VT Domain Scanner takes a file of domains, submits them to the Virus Total
# domain scanning API and outputs the domain and AV hits to a text file.

import time
import requests
import apikey
import csv

apikey = '' #### ENTER API KEY HERE ####

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
        r = requests.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

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
                print('{!r} is queued for scanning.'.format(domainSani))
                delay[domain] = 'queued'
            else:
                print(domainSani, 'was scanned successfully.')

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
        r = requests.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

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
                print(jsonResponse['verbose_msg'])

            elif jsonResponse['response_code'] == -2:
                print('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domainSani))

            else:
                print('Report is ready for', domainSani)

            # print(jsonResponse)
            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            ''' THIS SECTION IS FOR LATER DEV IMPLEMENTATION
            detections = {}
            for vendor, result in jsonResponse['scans'].items():  # sheer laziness of not having to reassign variables
                if 'clean site' not in result['result'] and 'unrated site' not in result['result']:
                    detections[vendor] = result['result']
            '''

            data = [scandate, domainSani, positives, total, permalink]
            return data, detections

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domainSani)

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
        time.sleep(10)
        DomainReportReader(domain, delay)


# I recognize that I'm keeping the file open this entire time and it may be a little more memory usage
# however, I'm tired and lazy atm and I presume you aren't going to
# open this for the file duration of the script
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
    with open('PATH TO FILE', 'r') as infile:
        tmp = file.readlines()
        for domain in tmp:
            delay = DomainScanner(domain)
            data = DomainReportReader(domain, delay)
            #dataWriter = csv.writer(file, delimiter=',')
            #dataWriter.writerow(data)
except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)

count = len(domainErrors)
if count > 0:
    print('There were {!s} errors scanning domains'.format(count))
