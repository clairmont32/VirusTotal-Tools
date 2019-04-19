package vtFileReport

import (
	"VirusTotal-Tools/go/src/vtapi"
	"bufio"
	"bytes"
	"encoding/csv"
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
func getHashReport(hash string) (buffer bytes.Buffer) {
	// http client settings
	client := http.Client{Timeout: time.Duration(5 * time.Second)}

	resp, postErr := client.PostForm("https://www.virustotal.com/vtapi/v2/file/report", url.Values{"apikey": {apikey.Key}, "resource": {hash}})
	if postErr != nil {
		log.Fatal(postErr)
	}

	// exit on HTTP 404
	if resp.StatusCode == http.StatusNotFound {
		fmt.Println("Hash not found")
		os.Exit(1)
	}

	if resp.StatusCode == http.StatusForbidden {
		fmt.Println("Received HTTP Forbidden. Did you forget to include your API key?")
		os.Exit(1)
	}

	// if ratelimited, sleep for 30s and try again. *Note* VT responds with HTTP 204 not 429 as they cut you off entirely
	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Pausing for 30s due to rate limiting!!!")
		time.Sleep(time.Second * 30)
		getHashReport(hash)
	}

	// return buffered HTTP response
	if resp.StatusCode == http.StatusOK {
		if _, bufErr := buffer.ReadFrom(resp.Body); bufErr != nil {
			fmt.Println(resp.Status)
			panic(bufErr)

		}
	} else {
		fmt.Println(resp.StatusCode)
		os.Exit(resp.StatusCode)
	}
	return
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

// open saved VT response for offline use. Not effective for large files
func openSavedResponse(filename string) []byte {
	if fileContent, readErr := ioutil.ReadFile(filename); readErr != nil {
		panic(readErr)
	} else {
		return fileContent
	}

}

func extractData(content *[]byte) (data [][]string, jsonResp *FileReport) {
	jsonResp = new(FileReport)
	if unmashErr := json.Unmarshal(*content, jsonResp); unmashErr != nil {
		panic(unmashErr)
	}

	// var data [][]string
	for vendor, details := range jsonResp.Scans {
		if details.Detected == true {
			tmp := []string{vendor, details.Result, details.Version}
			data = append(data, tmp)
		}
	}

	return data, jsonResp
}

func printDetections(data [][]string, jsonResp *FileReport) {
	for _, item := range data {
		fmt.Printf("Vendor: %v\n", item[0])
		fmt.Printf("Malware: %v\n", item[1])
		fmt.Printf("Version: %v\n\n", item[2])
	}
	fmt.Printf("Total: %v/%v \n", jsonResp.Positives, jsonResp.Total)
	fmt.Printf("Permalink: %v \n", jsonResp.Permalink)
}

func saveToCSV(content *[][]string) {
	if file, csvErr := os.Create("Detected.csv"); csvErr != nil {
		panic(csvErr)
	} else {
		defer func() {
			closeErr := file.Close()
			if closeErr != nil {
				panic(closeErr)
			}
		}()

		csvWriter := csv.NewWriter(file)
		header := []string{"Vendor", "Detection", "Version"}
		if writeErr := csvWriter.Write(header); writeErr != nil {
			panic(writeErr)
		}

		for _, line := range *content {
			writeErr := csvWriter.Write(line)
			if writeErr != nil {
				panic(writeErr)
			}
		}
		csvWriter.Flush()
		fmt.Println("Results written to CSV")

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

func SaveHashDetections(hash string) {
	buf := getHashReport(hash)
	rawContent := buf.Bytes()
	data, _ := extractData(&rawContent)
	saveToCSV(&data)
}
func PrintHashDetections(hash string) {
	buf := getHashReport(hash)
	rawContent := buf.Bytes()
	data, jsonResp := extractData(&rawContent)
	printDetections(data, jsonResp)

}

func SaveToJsonFile(hash string) {
	buf := getHashReport(hash)
	saveResponse(buf)

}
