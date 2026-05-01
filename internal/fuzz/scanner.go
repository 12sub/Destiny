package fuzz

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Result means endpoint has been found
type Result struct {
	URL		string
	StatusCode	int
	Type		string // "dir", "api", "file"
}

// StartFuzzer runs discovery Logic
func StartFuzzer(target string, wordlist []string, workers int, mode string) {
	// Ensure the target has a protocol
	if !string.HasPrefix(target, "http") {
		target = "http://" + target
	}
	jobs := make(chan string, len(wordlist))
	results := make(chan Result)
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func {
			defer wg.Done()
			client := &http.Client{Timeout: 3 * time.Second}
			for path := range jobs {
				fullURL := fmt.Sprintf("%s/%s", target, path)
				resp, err := client.Head(fullURL) // HEAD is faster than GET
				if err == nil {
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						results <- Result{URL: fullURL, StatusCode: resp.StatusCode, Type: mode}
					}
					resp.Body.Close()
				}
			}
		}()
	}

	// Sending paths to workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Printing the results
	for res := range results {
		fmt.Printf("[+] Found %s : %s (Status: %d)\n", res.Type, res.URL, res.StatusCode)
	}
}

func GetAPIWordlist() []string {
	return []string{
		"api/v1", "api/v2", "api/v3",
		"swagger", "swagger.json", "swagger-ui.html",
		"graphql", "graphiql",
		"v1/user", "v1/admin",
		"api/private", "api/internal",
	}
}