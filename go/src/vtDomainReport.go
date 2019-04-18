package main

import (
	"VirusTotal-Tools/go/src/vtapi"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

func getDomainReport(d string) {
	client := http.Client{Timeout: time.Duration(10) * time.Second}
	reportUrl := "http://www.virustotal.com/vtapi/v2/url/report"

	req, err := client.PostForm(reportUrl, url.Values{"apikey": {apikey.Key}, "resource": {"rockstargames.com"}})
	if err != nil {
		log.Fatalf("Improper request given\n %v", err)
	}
	if req.StatusCode == http.StatusNoContent {
		fmt.Println("Rate-limit exceeded. Trying again in 15 seconds...")
		time.Sleep(time.Duration(15) * time.Second)
		getDomainReport(d)
	}
}

func main() {

}
