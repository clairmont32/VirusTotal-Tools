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
	if _, err := os.Create("vt_response.json"); err != nil {
		panic(err)
	}
	if writeErr := ioutil.WriteFile("vt_response.json", buffer.Bytes(), os.ModeAppend); writeErr != nil {
		panic(writeErr)
	}
}

// open saved VT response for offline use. Not effective for large files
func openSavedResponse(filename string) []byte {
	if fileContent, readErr := ioutil.ReadFile(filename); readErr != nil {
		panic(readErr)
	} else {
		return fileContent
	}

}

type Status struct {
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

type FileScan struct {
	Detected  bool   `json:"detected"`
	Version   string `json:"version"`
	Result    string `json:"result"`
	UpdatedOn string `json:"update"`
}

type FileReport struct {
	Status
	Scans     map[string]FileScan `json:"scans"`
	Positives int                 `json:"positives"`
	Total     int                 `json:"total"`
	Vendor    string              `json:"vendors"`
	Detected  bool                `json:"detected"`
	Result    string              `json:"result"`
}

func main() {
	const hash = "292b42c94a99f6074258181080b46e31"

	// buf := getHashReport(hash)
	// saveResponse(buf)
	rawContent := openSavedResponse("vt_response.json")

	jsonResp := new(FileReport)
	if unmashErr := json.Unmarshal(rawContent, jsonResp); unmashErr != nil {
		panic(unmashErr)
	}
	for _, i := range jsonResp.Scans {
		if i.Detected == true {
			fmt.Println(i)
		}
	}

}
