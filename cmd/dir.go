package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
	"net/http"
)

type profile struct {
	Default    string `json:"default"`
	Shortlived string `json:"shortlived"`
}

type meta struct {
	ExternalAccountRequired bool    `json:"externalAccountRequired"`
	Profiles                profile `json:"profiles"`
	TermsOfService          string  `json:"termsOfService"`
}

type dir struct {
	KeyChange   string `json:"keyChange"`
	Meta        meta   `json:"meta"`
	NewAccount  string `json:"newAccount"`
	NewNonce    string `json:"newNonce"`
	NewOrder    string `json:"newOrder"`
	RenewalInfo string `json:"renewalInfo"`
	RevokeCert  string `json:"revokeCert"`
}

func retrieveDir(url string, certPool *x509.CertPool) (error, dir) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certPool},
	}

	httpClient := http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err, dir{}
	}

	req.Header.Set("User-Agent", network.AcmeClientName+"/"+network.AcmeClientVersion)

	res, err := httpClient.Do(req)
	if err != nil {
		return err, dir{}
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err, dir{}
	}

	// Init the data structure
	myProfile := profile{}
	myMeta := meta{Profiles: myProfile}
	myDir := dir{Meta: myMeta}

	err = json.Unmarshal(body, &myDir)
	if err != nil {
		return err, dir{}
	}

	return nil, myDir
}
