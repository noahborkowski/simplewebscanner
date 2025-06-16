package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// Issue represents a potential security problem found during scanning.
type Issue struct {
	URL     string `json:"url"`
	Message string `json:"message"`
}

func main() {
	baseURL := flag.String("url", "", "Base URL to scan")
	maxDepth := flag.Int("depth", 2, "Max crawl depth")
	outFile := flag.String("o", "", "Optional JSON report output file")
	workers := flag.Int("workers", 5, "Number of concurrent workers")
	flag.Parse()

	if *baseURL == "" {
		log.Fatal("base URL required")
	}

	u, err := url.Parse(*baseURL)
	if err != nil {
		log.Fatalf("invalid base URL: %v", err)
	}

	domain := u.Hostname()
	visited := make(map[string]bool)
	var vMu sync.Mutex

	var results []Issue
	var rMu sync.Mutex

	type task struct {
		url   string
		depth int
	}

	tasks := make(chan task, *workers)
	var workWG sync.WaitGroup // tracks outstanding tasks
	var workerWG sync.WaitGroup

	worker := func() {
		defer workerWG.Done()
		for t := range tasks {
			if t.depth < 0 {
				continue
			}
			vMu.Lock()
			if visited[t.url] {
				vMu.Unlock()
				continue
			}
			visited[t.url] = true
			vMu.Unlock()

			newIssues, links := scanPage(t.url, domain)
			if len(newIssues) > 0 {
				rMu.Lock()
				results = append(results, newIssues...)
				rMu.Unlock()
			}
			if t.depth > 0 {
				for _, l := range links {
					workWG.Add(1)
					tasks <- task{l, t.depth - 1}
				}
			}
			workWG.Done()
		}
	}

	for i := 0; i < *workers; i++ {
		workerWG.Add(1)
		go worker()
	}

	workWG.Add(1)
	tasks <- task{u.String(), *maxDepth}

	go func() {
		workWG.Wait()
		close(tasks)
	}()

	workerWG.Wait()

	for _, issue := range results {
		fmt.Printf("[+] %s - %s\n", issue.URL, issue.Message)
	}

	if *outFile != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		ioutil.WriteFile(*outFile, data, 0644)
	}
}

func scanPage(pageURL, domain string) ([]Issue, []string) {
	var issues []Issue
	var links []string

	resp, err := http.Get(pageURL)
	if err != nil {
		issues = append(issues, Issue{pageURL, fmt.Sprintf("request error: %v", err)})
		return issues, links
	}
	defer resp.Body.Close()

	// Check security headers
	checkHeader := func(name string) {
		if resp.Header.Get(name) == "" {
			issues = append(issues, Issue{pageURL, fmt.Sprintf("missing header: %s", name)})
		}
	}
	checkHeader("Content-Security-Policy")
	checkHeader("X-Frame-Options")
	checkHeader("X-Content-Type-Options")
	checkHeader("Strict-Transport-Security")

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	body := string(bodyBytes)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		issues = append(issues, Issue{pageURL, fmt.Sprintf("parse error: %v", err)})
		return issues, links
	}

	title := strings.ToLower(strings.TrimSpace(doc.Find("title").Text()))
	if strings.Contains(title, "admin") || strings.Contains(title, "login") ||
		strings.Contains(strings.ToLower(pageURL), "admin") || strings.Contains(strings.ToLower(pageURL), "login") {
		issues = append(issues, Issue{pageURL, "potential admin/login page"})
	}

	// Test payloads if input fields are present
	inputs := doc.Find("input[name]")
	if inputs.Length() > 0 {
		inputs.Each(func(i int, s *goquery.Selection) {
			name, _ := s.Attr("name")
			testPayload(pageURL, domain, name, "\"><script>alert(1)</script>", &issues)
			testPayload(pageURL, domain, name, "' OR '1'='1", &issues)
		})
	}

	// Find internal links
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		u, err := url.Parse(href)
		if err != nil {
			return
		}
		if !u.IsAbs() {
			u = resp.Request.URL.ResolveReference(u)
		}
		if u.Hostname() == domain {
			normalized := strings.TrimRight(u.String(), "/")
			links = append(links, normalized)
		}
	})

	return issues, links
}

func testPayload(pageURL, domain, inputName, payload string, issues *[]Issue) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return
	}
	q := u.Query()
	q.Set(inputName, payload)
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	if bytes.Contains(bodyBytes, []byte(payload)) {
		*issues = append(*issues, Issue{pageURL, fmt.Sprintf("payload reflected for %s: %s", inputName, payload)})
	}
}
