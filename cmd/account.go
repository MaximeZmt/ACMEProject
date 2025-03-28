package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/crypto"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
	"net/http"
	"strings"
)

type accountRequest struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

func createAccount(url string, nonce string, certPool *x509.CertPool) (string, string, *ecdsa.PrivateKey, error) {

	payload := accountRequest{
		TermsOfServiceAgreed: true,
		Contact:              []string{},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", "", nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certPool},
	}

	httpClient := http.Client{Transport: tr}

	pKey, err := crypto.GenerateNewKeys()
	if err != nil {
		return "", "", nil, err
	}

	myjws, err := network.NewJWS(nonce, url, pKey, jsonPayload, "")
	if err != nil {
		return "", "", nil, err
	}

	myjws.EncodedSignature = strings.Replace(myjws.EncodedSignature, "=", "", -1)
	myjson, _ := json.Marshal(myjws)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(myjson))
	if err != nil {
		return "", "", nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", network.AcmeClientName+"/"+network.AcmeClientVersion)

	res, err := httpClient.Do(req)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", "", nil, err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")
	if err != nil {
		return "", "", nil, err
	}

	if res.Header.Get("Replay-Nonce") == "" {
		return "", "", nil, errors.New("no Replay-Nonce")
	}

	if res.Header.Get("Location") == "" {
		return "", "", nil, errors.New("no Location")
	}

	return res.Header.Get("Replay-Nonce"), res.Header.Get("Location"), pKey, nil
}
