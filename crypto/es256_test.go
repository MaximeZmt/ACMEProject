package crypto

import (
	"testing"
)

func TestName(t *testing.T) {
	pKey, _ := GenerateNewKeys()
	payload := []byte("test")
	signature, _ := Sign(pKey, payload)
	pubKey := pKey.PublicKey
	check, _ := Verify(&pubKey, payload, signature)
	if check == false {
		t.Errorf("Check is wrong")
	}
}
