package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/crypto"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
)

type postCsr struct {
	Csr string `json:"csr"`
}

func genCertif(netState *network.StateNetwork, url string, domain []string) (*ecdsa.PrivateKey, error) {

	certifKeys, err := crypto.GenerateNewKeys()
	if err != nil {
		return nil, err
	}

	certReq, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: domain[0],
			Country:    []string{"CH"},
		},
		DNSNames: domain,
	}, certifKeys)

	csr := base64.RawURLEncoding.EncodeToString(certReq)

	csrStruct := postCsr{csr}

	jsonPayload, err := json.Marshal(csrStruct)
	if err != nil {
		return nil, err
	}

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	return certifKeys, nil
}

func downloadCertificate(netState *network.StateNetwork, url string) (string, error) {

	jsonPayload := []byte("")

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	return string(body), nil
}
