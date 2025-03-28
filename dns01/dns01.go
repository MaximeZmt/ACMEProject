package dns01

import (
	"fmt"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server store the server object. Used to shut down from outside context.
var Server *dns.Server

// dnsARecord A record use by the CI to map the IP to the domain
var dnsARecord = ""

// tokensList list of TXT record for the ACME Protocol
var tokensList []string

// mu Mutex to protect access to the list
var mu sync.RWMutex

func handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg).SetReply(r)

	mu.RLock()
	defer mu.RUnlock()

	for _, q := range m.Question {
		// Handle TXT ACME protocol query
		if q.Qtype == dns.TypeTXT {
			for _, t := range tokensList {
				rr, err := dns.NewRR(fmt.Sprintf("_acme-challenge.%s TXT \"%s\"", q.Name, t))
				if err != nil {
					logger.Logger().Error().Msgf("Could not create Resource Record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}

			// Handle A protocol query
		} else if q.Qtype == dns.TypeA {
			rr, err := dns.NewRR(fmt.Sprintf("%s A "+dnsARecord, q.Name))
			if err != nil {
				logger.Logger().Error().Msgf("Could not create Resource Record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		logger.Logger().Error().Msgf("Error while writing DNS Answer: %v", err)
		return
	}
}

func DNS01(tokenChannel <-chan string, ip string) {

	go func() {
		for {
			select {
			case s := <-tokenChannel: // Receive tokens as normal
				mu.Lock()
				tokensList = append(tokensList, s)
				logger.Logger().Debug().Msgf("Token added: ", s)
				mu.Unlock()
			case <-time.After(100 * time.Millisecond): // When done is closed, exit the loop
				continue
			}
		}
	}()

	// Setup DNS Server according to ACME Protocol
	Server = &dns.Server{
		Addr:    "0.0.0.0:10053",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	// Set the DNS Record for A answer
	dnsARecord = ip

	if err := Server.ListenAndServe(); err != nil {
		logger.Logger().Error().Msgf("Could not start dns01 server: %v", err)
	}
}
