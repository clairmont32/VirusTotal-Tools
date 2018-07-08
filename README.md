# VT-Domain-Scanner
Takes an input file with domains on each line and passes them to the VT API then writes the following items to a CSV.
* Most recent scan date/time
* Sanitized domain
* Count of non-clean detections
* Total AV scans
* Link to scan results

## Prerequisites 
* Python 3.x+
* VirusTotal API key
* requests library

```pip install requests```

### Example usecases
* Scan list of domains from an investigation
* PiHole domain nightly scans
* DNS log domain scans
* Periodic network traffic scans


### Feature requests and bug reports
Please submit feature requests and bug reports through the issues page for this project.
