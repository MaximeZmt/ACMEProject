package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"net/http"
)

func retrieveNonce(url string, certPool *x509.CertPool) (error, string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certPool},
	}

	httpClient := http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err, ""
	}

	req.Header.Set("User-Agent", network.AcmeClientName+"/"+network.AcmeClientVersion)

	res, err := httpClient.Do(req)
	if err != nil {
		return err, ""
	}

	if res.Header.Get("Replay-Nonce") == "" {
		return errors.New("empty Nonce"), ""
	}

	return nil, res.Header.Get("Replay-Nonce")
}
