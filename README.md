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

  
