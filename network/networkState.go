package network

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
)

type StateNetwork struct {
	nonce    string
	kid      string
	pKey     *ecdsa.PrivateKey
	certPool *x509.CertPool
}

func NewStateNetwork(pKey *ecdsa.PrivateKey, certPool *x509.CertPool, kid string) StateNetwork {
	return StateNetwork{
		nonce:    "",
		kid:      kid,
		pKey:     pKey,
		certPool: certPool,
	}
}

func (netState *StateNetwork) SetNonce(newNonce string) error {
	if newNonce != "" {
		netState.nonce = newNonce
		return nil
	}

	return errors.New("trying to set an empty nonce")
}

func (netState *StateNetwork) GetNonce() string {
	return netState.nonce
}
