package main

import (
	"VirusTotal-Tools/vtapi"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// send a hash to VT
func getHashReport(hash string) bytes.Buffer {
	client := http.Client{Timeout: time.Duration(5 * time.Second)}
	var buffer bytes.Buffer

	resp, postErr := client.PostForm("https://www.virustotal.com/vtapi/v2/file/report", url.Values{"apikey": {apikey.Key}, "resource": {hash}})
	if postErr != nil {
		log.Fatal(postErr)
	}
	if resp.StatusCode == http.StatusOK {
		if n, bufErr := buffer.ReadFrom(resp.Body); bufErr == nil {
			fmt.Printf("Bytes %v \n", n)
			// fmt.Print(buffer.String())
		}

	}
	return buffer
}

//  save response for offline dev/minimal API usage
func saveResponse(buffer bytes.Buffer) {
	// check for presence of detected.csv
	// create if it does not exist
	// open, write header, write rows, close

}

// open saved VT response for offline use. Not effective for large files
func openSavedResponse(filename string) []byte {
	if fileContent, readErr := ioutil.ReadFile(filename); readErr != nil {
		panic(readErr)
	} else {
		return fileContent
	}

}

// declare variables and types for items in the json we care about
type Status struct {
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

type VendorResults struct {
	Detected  bool   `json:"detected"`
	Version   string `json:"version"`
	Result    string `json:"result"`
	UpdatedOn string `json:"update"`
}

type FileReport struct {
	Status
	Positives int                      `json:"positives"`
	Total     int                      `json:"total"`
	Permalink string                   `json:"permalink"`
	Scans     map[string]VendorResults `json:"scans"`
}

func printDetections(content []byte) {
	jsonResp := new(FileReport)
	if unmashErr := json.Unmarshal(content, jsonResp); unmashErr != nil {
		panic(unmashErr)
	}

	for vendor, details := range jsonResp.Scans {
		if details.Detected == true {
			fmt.Printf("Vendor: %v \n", vendor)
			fmt.Printf("Result: %v \n", details.Result)
			fmt.Printf("Version: %v \n\n", details.Version)
		}
	}

	fmt.Printf("Total: %v/%v \n", jsonResp.Positives, jsonResp.Total)
	fmt.Printf("Permalink: %v \n", jsonResp.Permalink)
}

func saveToCSV(content []byte) {
	if _, csvErr := os.Create("Detected.csv"); csvErr != nil {
		panic(csvErr)
	}

	csvWriter := encoding/csv.

}

func main() {
	const hash = "292b42c94a99f6074258181080b46e31"

	// buf := getHashReport(hash)
	// saveResponse(buf)
	rawContent := openSavedResponse("vt_response.json")
	printDetections(rawContent)

}
