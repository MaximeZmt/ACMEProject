package httpShutdown

import (
	"errors"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"net/http"
)

// Server store the server object. Used to shut down from outside context.
var Server *http.Server

// ShutdownChannel is a go chan that send to the main code a Shutdown signal
var ShutdownChannel chan string

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/shutdown" {
		logger.Logger().Debug().Msgf("Received a Shutdown signal")

		// Send a signal to the main code
		ShutdownChannel <- "SleepySignal"

		// Answer HTTP request
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Other path of the server does not exist
	w.WriteHeader(http.StatusNotFound)
}

func HTTPShutdown() {
	// ShutdownChannel initialization.
	ShutdownChannel = make(chan string)

	Server = &http.Server{
		Addr:    "0.0.0.0:5003",
		Handler: http.HandlerFunc(handler),
	}
	if err := Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Logger().Error().Msgf("Could not start http shutdown server: %v", err)
	}
}
