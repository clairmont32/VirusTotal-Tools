package main

import (
	"bytes"
	"fmt"
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
func hashReport(apiKey string, hash string) {
	client := http.Client{Timeout: time.Duration(5 * time.Second)}
	var buffer bytes.Buffer

	resp, postErr := client.PostForm("https://www.virustotal.com/vtapi/v2/file/report", url.Values{"apikey": {apiKey}, "resource": {hash}})
	if postErr != nil {
		log.Fatal(postErr)
	}
	if resp.StatusCode == http.StatusOK {
		if n, bufErr := buffer.ReadFrom(resp.Body); bufErr == nil {
			fmt.Printf("Bytes %v \n", n)
			fmt.Print(buffer.String())
		} else {
			fmt.Println(bufErr)
		}

		return
	}
}

func main() {
	const hash = "292b42c94a99f6074258181080b46e31"
	apiKey := getApiKey()
	hashReport(apiKey, hash)

}
