package main

import (
	"VirusTotal-Tools/src/vtapi"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

// send a hash to VT
func getHashReport(apikey string, hash string) bytes.Buffer {
	client := http.Client{Timeout: time.Duration(5 * time.Second)}
	var buffer bytes.Buffer

	resp, postErr := client.PostForm("https://www.virustotal.com/vtapi/v2/file/report", url.Values{"apikey": {apikey}, "resource": {hash}})
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

// open saved VT response for offline use. Not effective for large files
func openSavedResponse(filename string) []byte {
	if fileContent, readErr := ioutil.ReadFile(filename); readErr != nil {
		panic(readErr)
	} else {
		return fileContent
	}

}
func main() {
	const hash = "292b42c94a99f6074258181080b46e31"
	const apiKey = apikey.Key

	// buf := getHashReport(apiKey, hash)
	rawContent := openSavedResponse("vt_response.txt")
	fmt.Print(string(rawContent))
}
