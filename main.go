package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)

func main() {
	var wg sync.WaitGroup

	freeDomains := []string{}

	i := 1
	for r := 'a'; r <= 'z'; r++ {
		wg.Add(1)
		go runForLetter(&wg, &freeDomains, fmt.Sprintf("%c", r))
		i++
	}

	wg.Wait()

	writeLinesToFile(freeDomains)

	log.Printf("Done!")
}

func runForLetter(wg *sync.WaitGroup, freeDomains *[]string, letter string) {
	defer wg.Done()

	domainsToCheck := generateInput()

	for _, domain := range domainsToCheck {
		log.Printf("Checking " + letter + domain + ".nz")
		resp, err := checkDomain(letter + domain + ".nz")
		if err != nil {
			log.Fatal(err)
		}

		if resp {
			*freeDomains = append(*freeDomains, letter+domain+".nz")
		}
	}

	fmt.Printf("Worker %s: Finished\n", letter)
}

// checkDomain - True if available, error/false if not
func checkDomain(domain string) (bool, error) {
	time.Sleep(time.Millisecond * 150)
	resultRaw, err := whois.Whois(domain, "whois.srs.net.nz")
	if err != nil {
		return false, err
	}

	_, err = whoisparser.Parse(resultRaw)
	if err != nil {
		if err.Error() == "whoisparser: domain is not found" {
			return true, nil
		}

		return false, err
	}

	return false, err
}

func generateInput() []string {
	output := []string{}

	for r := 'a'; r <= 'z'; r++ {
		for x := 'a'; x <= 'z'; x++ {
			output = append(output, fmt.Sprintf("%c", r)+fmt.Sprintf("%c", x))
		}
	}

	return output
}

func writeLinesToFile(str []string) {
	if len(str) == 0 {
		return
	}

	file, err := os.OpenFile("3char.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	datawriter := bufio.NewWriter(file)

	for _, data := range str {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()
}
