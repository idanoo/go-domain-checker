package main

import (
	"fmt"
	"log"
	"time"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)

func main() {
	freeDomains := []string{}

	domainsToCheck := generateInput()

	for _, domain := range domainsToCheck {
		resp, err := checkDomain(domain)
		if err != nil {
			log.Fatal(err)
		}

		if resp {
			log.Printf("%s is free!", domain)
			freeDomains = append(freeDomains, domain)
		} else {
			log.Printf("%s is not free!", domain)
		}
	}

	log.Println()
	log.Println("Free Domains:")

	for _, v := range freeDomains {
		log.Print(v)
	}

}

// checkDomain - True if available, error/false if not
func checkDomain(domain string) (bool, error) {
	time.Sleep(time.Second * 5)
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

	for o := 'a'; o <= 'z'; o++ {
		for r := 'a'; r <= 'z'; r++ {
			output = append(output, fmt.Sprintf("%c", o)+fmt.Sprintf("%c", r))
		}
	}

	return output
}
