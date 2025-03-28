package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

func GenerateNewKeys() (*ecdsa.PrivateKey, error) {
	pKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return pKey, nil
}

func Sign(pKey *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, pKey, hash[:])
	if err != nil {
		return "", err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure that r and s are padded to 32 bytes each (P-256 curve)
	rBytes = append(make([]byte, 32-len(rBytes)), rBytes...)
	sBytes = append(make([]byte, 32-len(sBytes)), sBytes...)

	// Combine r and s
	signature := append(rBytes, sBytes...)

	return base64.URLEncoding.EncodeToString(signature), nil
}

func Verify(pubKey *ecdsa.PublicKey, data []byte, signature string) (bool, error) {
	hash := sha256.Sum256(data)

	signatureDecodedByte, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	rBytes := signatureDecodedByte[:32]
	sBytes := signatureDecodedByte[32:]

	var r, s big.Int

	r.SetBytes(rBytes)
	s.SetBytes(sBytes)

	return ecdsa.Verify(pubKey, hash[:], &r, &s), nil
}
