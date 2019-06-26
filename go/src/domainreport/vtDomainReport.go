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

func getApiEnv() string {
	if len(os.Getenv("VT")) > 0 {
		return os.Getenv("VT")
	} else {
		log.Fatal("No API key set in environment variables!")
	}
	return ""
}

func getDomainReport(d string) (buffer bytes.Buffer, sanitizedDomain string) {
	sanitizedDomain = strings.ReplaceAll(d, ".", "[.]")

	client := http.Client{Timeout: time.Duration(10) * time.Second}
	reportUrl := "http://www.virustotal.com/vtapi/v2/domain/report"
	resp, err := client.PostForm(reportUrl, url.Values{"apikey": {getApiEnv()}, "resource": {d}})
	if err != nil {
		log.Fatalf("Improper requeest given\n %v", err)
	}

	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Rate-limit exceeded. Trying again in 15 seconds...")
		time.Sleep(time.Duration(15) * time.Second)
		getDomainReport(d)
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
	if response.Status.ResponseCode == 0 {
		fmt.Printf("%v has not been observed by VirusTotal\n", sDomain)
	} else if response.Status.ResponseCode == -2 {
		fmt.Printf("%v is queued for scanning. Checking for results in 15s", sDomain)
		time.Sleep(15 * time.Second)
		getDomainReport(d)
	} else if response.Status.ResponseCode == 1 {
		return // TODO: continue processing
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

	fmt.Println("File saved")
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
	bufContent, _ := getDomainReport("google.com")
	var content UrlReport
	_ = json.Unmarshal(bufContent.Bytes(), &content)
	saveResponse(bufContent)

	// checkVtResponseCode(content, sanitizedDomain, "google.com")

}
