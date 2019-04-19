package main

import (
	"VirusTotal-Tools/go/src/vtapi"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

func getDomainReport(d string) (buffer bytes.Buffer) {
	client := http.Client{Timeout: time.Duration(10) * time.Second}
	reportUrl := "http://www.virustotal.com/vtapi/v2/url/report"

	resp, err := client.PostForm(reportUrl, url.Values{"apikey": {apikey.Key}, "resource": {d}})
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

type Status struct {
	ResponseCode	int		`json:"response_code"`
	Resource		string	`json:"resource"`
	VerboseMsg		string	`json:"verbose_msg"`
}

type UrlReport struct {
	Status

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

	// if writing fails 3 times, log and exit
	for i := 0; i <= 3; {
		_, writeErr := writer.Write(buffer.Bytes())
		if writeErr != nil {
			time.Sleep(time.Millisecond * 200)
			i++
			fmt.Println("Could not write contents to file %v", writeErr)
		}
		break

	}

	// flush and close file
	if flushErr := writer.Flush(); flushErr != nil {
		log.Printf("Could not flush content to %v\n%v", filename, flushErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		log.Printf("Error closing %v \n%v", filename, closeErr)
	}

}


func main() {
 // TODO: verify above works. Write a test for VT response codes?

 bufContent := getDomainReport("rockstargames.com")

 var content UrlReport
	_ = json.Unmarshal(bufContent.Bytes(), &content)

saveResponse(bufContent)


}
