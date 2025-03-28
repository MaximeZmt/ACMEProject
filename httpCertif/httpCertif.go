package httpCertif

import (
	"crypto/tls"
	"errors"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"log/slog"
	"net/http"
)

// Server store the server object. Used to shut down from outside context.
var Server *http.Server

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func HTTPCertificate(certBody string, certKey string) {

	cert, err := tls.X509KeyPair([]byte(certBody), []byte(certKey))
	if err != nil {
		slog.Error("Could not start http Certificate server", "err", err)
	}

	Server = &http.Server{
		Addr:    "0.0.0.0:5001",
		Handler: http.HandlerFunc(handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	if err := Server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Logger().Error().Msgf("Could not start http certificate server: %v", err)
	}
}
