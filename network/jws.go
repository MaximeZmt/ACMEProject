package network

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/crypto"
	"net/http"
	"strings"
)

var AcmeClientName string = "RoadRunner"
var AcmeClientVersion string = "0.0.1"

type JWS struct {
	EncodedHeader    string `json:"protected"`
	EncodedPayload   string `json:"payload"`
	EncodedSignature string `json:"signature"`
}

type JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwsHeaderCreation struct {
	Alg   string `json:"alg"`
	Jwk   JWK    `json:"jwk"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
}

type jwsHeaderExisting struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	Url   string `json:"url"`
}

func SendPayloadThroughJWS(jsonPayload []byte, url string, netState *StateNetwork) (*http.Response, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: netState.certPool},
	}

	httpClient := http.Client{Transport: tr}

	myjws, err := NewJWS(netState.nonce, url, netState.pKey, jsonPayload, netState.kid)
	if err != nil {
		return nil, err
	}

	myjws.EncodedSignature = strings.Replace(myjws.EncodedSignature, "=", "", -1)
	myjson, _ := json.Marshal(myjws)

	fmt.Printf("\nmyjson: " + string(myjson) + "\n")

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(myjson))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", AcmeClientName+"/"+AcmeClientVersion)

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	err = netState.SetNonce(res.Header.Get("Replay-Nonce"))
	if err != nil {
		return nil, err
	}

	return res, err
}

func NewJWS(nonce string, url string, pKey *ecdsa.PrivateKey, jsonPayload []byte, kid string) (JWS, error) {
	xtostring := base64.RawURLEncoding.EncodeToString(pKey.PublicKey.X.Bytes())
	ytostring := base64.RawURLEncoding.EncodeToString(pKey.PublicKey.Y.Bytes())

	var err error
	var jsonHeader []byte

	if kid != "" {
		header := jwsHeaderExisting{
			Alg:   "ES256",
			Nonce: nonce,
			Url:   url,
			Kid:   kid,
		}
		jsonHeader, err = json.Marshal(header)
	} else {
		jwk := JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   xtostring,
			Y:   ytostring,
		}
		header := jwsHeaderCreation{
			Alg:   "ES256",
			Nonce: nonce,
			Url:   url,
			Jwk:   jwk,
		}
		jsonHeader, err = json.Marshal(header)
	}
	if err != nil {
		return JWS{}, nil
	}

	base64Header := base64.URLEncoding.EncodeToString(jsonHeader)
	base64Header = strings.Replace(base64Header, "=", "", -1)

	base64Payload := base64.URLEncoding.EncodeToString(jsonPayload)
	base64Payload = strings.Replace(base64Payload, "=", "", -1)

	base64Signature, err := jwsSign(pKey, base64Header, base64Payload)
	if err != nil {
		return JWS{}, err
	}

	generatedJWS := JWS{
		EncodedHeader:    base64Header,
		EncodedPayload:   base64Payload,
		EncodedSignature: base64Signature,
	}

	return generatedJWS, nil
}

func jwsSign(pKey *ecdsa.PrivateKey, base64Header string, base64Payload string) (string, error) {

	signature, _ := crypto.Sign(pKey, []byte(base64Header+"."+base64Payload))

	return signature, nil
}

func X509keysStringForDebug(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	pKeyX509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pKeyX509Encoded})

	pubKeyX509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyX509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}
