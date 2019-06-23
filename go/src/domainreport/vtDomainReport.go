package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func getApiEnv() (apiKey string) {
	allEnvs := os.Environ()
	for _, env := range allEnvs {
		if strings.Contains(env, "VTAPI") {
			apiKey = strings.Split(env, "=")[1]
			return
		}
	}
	return "No API key set in environment variables!"
}

func getDomainReport(d string, apiKey string) (buffer bytes.Buffer, sanitizedDomain string) {
	client := http.Client{Timeout: time.Duration(10) * time.Second}
	reportUrl := "http://www.virustotal.com/vtapi/v2/url/report"
	resp, err := client.PostForm(reportUrl, url.Values{"apikey": {apiKey}, "resource": {d}})

	sanitizedDomain = strings.ReplaceAll(d, ".", "[.]")

	if err != nil {
		log.Fatalf("Improper requeest given\n %v", err)
	}
	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Rate-limit exceeded. Trying again in 15 seconds...")
		time.Sleep(time.Duration(15) * time.Second)
		getDomainReport(d, getApiEnv())
	}

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("No results found for %v", sanitizedDomain)
	}

	if resp.StatusCode == http.StatusOK {
		if _, bufErr := buffer.ReadFrom(resp.Body); bufErr != nil {
			log.Fatalf("Failed to read response into buffer\n%v", bufErr)
		}
		return buffer, sanitizedDomain
	}
	return
}

type Status struct {
	ResponseCode int    `json:"response_code"`
	Resource     string `json:"resource"`
	VerboseMsg   string `json:"verbose_msg"`
}

type UrlReport struct {
	Status
}

func checkVtResponseCode(response UrlReport, sDomain string, d string) {
	if response.ResponseCode == 0 {
		fmt.Printf("%v has not been observed by VirusTotal", sDomain)
	} else if response.ResponseCode == -2 {
		fmt.Printf("%v is queued for scanning. Checking for results in 15s", sDomain)
		time.Sleep(15 * time.Second)
		getDomainReport(d, getApiEnv())
	} else if response.ResponseCode == 1 {
		// TODO: continue extracting malicious results and outputting to console/csv
	}

}

// save response to file for offline use
func saveResponse(buffer bytes.Buffer) {
	filename := "vt_response.json"

	// if the file doesnt exist, create it. if it does, truncate the contents
	file, createErr := os.Create(filename)
	if createErr != nil {
		log.Printf("Could not create %v\n%v", filename, createErr)
		return

	}

	// buffer the writer
	writer := bufio.NewWriter(file)
	_, bufWrErr := writer.Write(buffer.Bytes())
	if bufWrErr != nil {
		log.Fatalf("Could not write to buffer.\n%v", bufWrErr)
	}

	// flush and close file
	if flushErr := writer.Flush(); flushErr != nil {
		log.Printf("Could not flush content to %v\n%v", filename, flushErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		log.Printf("Error closing %v \n%v", filename, closeErr)
	}

}

// temp func to save VT response
func parseToJson(buffer bytes.Buffer) (jsonResp UrlReport) {
	jsonErr := json.Unmarshal(buffer.Bytes(), &jsonResp)
	if jsonErr != nil {
		log.Fatalf("Could not parse JSON response\n%v", jsonErr)
	}
	return
}

func arguments() {
	//TODO add cli arguments for single domain or file of only domains
}

func main() {
	// TODO: verify above works. Write a test for VT response codes?
	bufContent, sanitizedDomain := getDomainReport("rockstargames.com", getApiEnv())
	var content UrlReport
	_ = json.Unmarshal(bufContent.Bytes(), &content)

	checkVtResponseCode(content, sanitizedDomain, "rockstargames.com")

	saveResponse(bufContent)

}
