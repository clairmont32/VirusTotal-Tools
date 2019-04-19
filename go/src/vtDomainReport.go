package main

import (
	"VirusTotal-Tools/go/src/vtapi"
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

func getDomainReport(d string) (buffer bytes.Buffer) {
	client := http.Client{Timeout: time.Duration(10) * time.Second}
	reportUrl := "http://www.virustotal.com/vtapi/v2/url/report"

	resp, err := client.PostForm(reportUrl, url.Values{"apikey": {apikey.Key}, "resource": {"rockstargames.com"}})
	if err != nil {
		log.Fatalf("Improper requeest given\n %v", err)
	}
	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Rate-limit exceeded. Trying again in 15 seconds...")
		time.Sleep(time.Duration(15) * time.Second)
		getDomainReport(d)
	}

	if resp.StatusCode == http.StatusNotFound {
		// TODO: sanitize domain for printing/logging
		fmt.Printf("No results found for %v", d)
	}

	if resp.StatusCode == http.StatusOK {
		if _, bufErr := buffer.ReadFrom(resp.Body); bufErr != nil {
			log.Fatalf("Failed to read response into buffer\n%v", bufErr)
		}
		return buffer
	}
	return
}

func main() {
 // TODO: verify above works. Write a test for VT response codes?

}
