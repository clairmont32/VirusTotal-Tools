"""
Prompt for apikey
Prompt for hash
Request hash report from VT
Parse only non-clean detections- AV name, detection name, version/definitions, VT updated date
Print above info
"""

import requests
from time import sleep


# requests setup
requests.urllib3.disable_warnings()
client =  requests.session()
client.verify = False

apikey = input('Enter your API key.')


def get_hash_report(apikey, filehash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {"apikey": apikey, "resource": filehash, "allinfo": True}

    # perform call
    r = client.get(url, params=params)

    if r.status_code == 429:
        print('Encountered rate-limiting. Sleeping for 45 seconds.')
        sleep(45)
        get_hash_report(apikey, filehash)

    elif r.status_code != 200:
        print('Encountered unanticipated HTTP error.')
        print(r.status_code)
        exit(1)

    elif r.status_code == 200:
        response = r.json()
        parse_hash_report(response)


def parse_hash_report(response):
    detections = response['positives']
    if detections >= 1:
        scan_results = response['scans']

        print('\nAV Name, Malware Name, Definitions Version, Last Updated')
        for vendor in scan_results:
            if scan_results[vendor]['detected']:

                info_date = scan_results[vendor]['update']
                detected_name = scan_results[vendor]['result']
                definition_version = scan_results[vendor]['version']

                print('{!s}, {!s}, {!s}, {!s}'.format(vendor, detected_name, definition_version, info_date))
    else:
        print('No malicious detections found.')


while True:
    filehash = input('Enter a file hash: \n')
    get_hash_report(apikey, filehash)
