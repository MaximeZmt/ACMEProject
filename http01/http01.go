package http01

import (
	"errors"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server store the server object. Used to shut down from outside context.
var Server *http.Server

// tokensList contains a list of tokens served on the HTTP server used for validation of ACME protocol
var tokensList []string

// mu Mutex to protect access to the list
var mu sync.RWMutex

func handler(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	// Provide a valid HTTP path for each challenge token
	for _, token := range tokensList {
		if r.URL.Path == "/.well-known/acme-challenge/"+strings.Split(token, ".")[0] {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, err := io.WriteString(w, token)
			if err != nil {
				logger.Logger().Error().Msgf("Error while writing HTTP answer: %v", err)
			}
			return
		}
	}

	// In case it is not handling any token
	w.WriteHeader(http.StatusNotFound)
}

func HTTP01(tokenChannel <-chan string) {

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

	// Setup HTTP Server according to ACME Protocol
	Server = &http.Server{
		Addr:    "0.0.0.0:5002",
		Handler: http.HandlerFunc(handler),
	}

	if err := Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Logger().Error().Msgf("Could not start http01 server: %v", err)
	}
}
