# VT-Domain-Scanner
Takes an input file with domains or IPs on each line and passes them to the VT API then writes the following items to a CSV. 
IPs that are put through this scanner is effectively doing a HTTP/HTTPS check to see if a direct IP connection is malicious.
  * Most recent scan date/time
  * Sanitized domain
  * Count of non-clean detections
  * Total AV scans
  * Link to scan results

## Exe Version
Exe version of the script has been modified for CLI usage. It will still write the same information as the script to a CSV file which is written to the directory where the script is run from.
  * Prompts for API key
  * Status of key (public/private)
  * Filepath to a file

## Script Prerequisites 
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
