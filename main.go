package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	domain        string
	listFile      string
	outputFile    string
	silent        bool
	timeout       int
	concurrency   int
	uniqueDomains sync.Map
	client        *http.Client
	bannerShown   bool
)

func init() {
	flag.StringVar(&domain, "d", "", "Single target domain")
	flag.StringVar(&listFile, "l", "", "File containing list of domains")
	flag.StringVar(&outputFile, "o", "", "File to write output to")
	flag.BoolVar(&silent, "silent", false, "Show only results in output (hide banner)")
	flag.IntVar(&timeout, "t", 7, "API Timeout in seconds")
	flag.IntVar(&concurrency, "c", 10, "Maximum concurrency for processing multiple domains")

	flag.Usage = func() {
		showBanner()
		fmt.Fprintf(os.Stderr, "Usage:\n  shiro [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}
}

func showBanner() {
	if bannerShown {
		return
	}

	banner := "\n" +
		".|'''|. '||                        \n" +
		"||       ||      ''                \n" +
		"`|'''|,  ||''|,  ||  '||''| .|''|, \n" +
		"     ||  ||  ||  ||   ||    ||  || \n" +
		"'|...|' .||  || .||. .||.   `|..|' \n" +
		"                                   \n" +
		"      openverselabs - v0.1.0       \n"
	fmt.Fprintln(os.Stderr, banner)

	bannerShown = true
}

func main() {
	flag.Parse()

	if !silent {
		showBanner()
	}

	var outWriter *os.File
	if outputFile != "" {
		var err error
		outWriter, err = os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}
		defer outWriter.Close()
	}

	client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
		},
	}

	jobs := make(chan string)
	results := make(chan string, 500)

	var wg sync.WaitGroup
	var outWg sync.WaitGroup

	outWg.Add(1)
	go func() {
		defer outWg.Done()
		for sub := range results {
			if _, exists := uniqueDomains.LoadOrStore(sub, true); !exists {
				fmt.Println(sub)
				if outWriter != nil {
					outWriter.WriteString(sub + "\n")
				}
			}
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				enumerateDomain(d, results)
			}
		}()
	}

	if domain != "" {
		jobs <- domain
	} else if listFile != "" {
		file, err := os.Open(listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			d := strings.TrimSpace(scanner.Text())
			if d != "" {
				jobs <- d
			}
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			flag.Usage()
			os.Exit(0)
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			d := strings.TrimSpace(scanner.Text())
			if d != "" {
				jobs <- d
			}
		}
	}

	close(jobs)
	wg.Wait()
	close(results)
	outWg.Wait()
}

func enumerateDomain(target string, results chan<- string) {
	var apiWg sync.WaitGroup
	sources := []func(string, chan<- string, *sync.WaitGroup){
		runCrtSh,
		runAlienVault,
		runHackerTarget,
		runJLDC,
		runThreatMiner,
		runThreatCrowd,
		runURLScan,
		runWayback,
	}

	for _, source := range sources {
		apiWg.Add(1)
		go source(target, results, &apiWg)
	}
	apiWg.Wait()
}

func runCrtSh(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, entry := range data {
			subs := strings.Split(entry.NameValue, "\n")
			for _, sub := range subs {
				cleanSub := strings.TrimSpace(strings.ReplaceAll(sub, "*.", ""))
				if strings.HasSuffix(cleanSub, domain) {
					results <- cleanSub
				}
			}
		}
	}
}

func runAlienVault(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, entry := range data.PassiveDNS {
			cleanSub := strings.TrimSpace(strings.ReplaceAll(entry.Hostname, "*.", ""))
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runHackerTarget(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) > 0 {
			cleanSub := strings.TrimSpace(parts[0])
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runJLDC(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data []string
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, sub := range data {
			cleanSub := strings.TrimSpace(strings.ReplaceAll(sub, "*.", ""))
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runThreatMiner(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Results []string `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, sub := range data.Results {
			cleanSub := strings.TrimSpace(sub)
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runThreatCrowd(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, sub := range data.Subdomains {
			cleanSub := strings.TrimSpace(sub)
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runURLScan(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, entry := range data.Results {
			cleanSub := strings.TrimSpace(entry.Page.Domain)
			if strings.HasSuffix(cleanSub, domain) {
				results <- cleanSub
			}
		}
	}
}

func runWayback(domain string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := client.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain))
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for i, entry := range data {
			if i == 0 || len(entry) < 1 {
				continue
			}
			parsedURL, err := url.Parse(entry[0])
			if err == nil && parsedURL.Host != "" {
				cleanSub := strings.TrimSpace(parsedURL.Host)
				if idx := strings.Index(cleanSub, ":"); idx != -1 {
					cleanSub = cleanSub[:idx]
				}
				if strings.HasSuffix(cleanSub, domain) {
					results <- cleanSub
				}
			}
		}
	}
}
