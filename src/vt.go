package main

import (
	"fmt"
	"os"
	"strings"
)

// Local key is set as in ENV to avoid accidental commits with it in code
func getApiKey() (apiKey string) {
	env := os.Environ()
	for _, v := range env {
		if strings.Contains(v, "VT") {
			envVar := strings.Split(v, "=")
			return envVar[1]
		}
	}
	return
}

func main() {
	fmt.Println(getApiKey())
}
