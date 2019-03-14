package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Local key is set as in ENV to avoid accidental commits with it in code
func getApiKey() string {
	env := os.Environ()
	for _, v := range env {
		if strings.Contains(v, "VT") {
			envVar := strings.Split(v, "=")
			return envVar[1]
		}
	}
	return ""
}

// send a hash to VT
func getHashReport(apiKey string, hash string) bytes.Buffer {
	client := http.Client{Timeout: time.Duration(5 * time.Second)}
	var buffer bytes.Buffer

	resp, postErr := client.PostForm("https://www.virustotal.com/vtapi/v2/file/report", url.Values{"apikey": {apiKey}, "resource": {hash}})
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
	// const hash = "292b42c94a99f6074258181080b46e31"
	// apiKey := getApiKey()
	// buf := getHashReport(apiKey, hash)
	// rawContent := openSavedResponse("vt_response.txt")

}
