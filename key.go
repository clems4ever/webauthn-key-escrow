package main

import (
	"encoding/binary"
	"math/rand"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

// Key represents the key model
type Key struct {
	id          uint64
	kid         string
	content     string
	credentials []webauthn.Credential
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// NewKid creates and returns a new kid
func NewKey(kid string) *Key {

	key := &Key{}
	key.id = randomUint64()
	key.kid = kid
	key.content = RandomString(32)
	return key
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the key's ID
func (k Key) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(k.id))
	return buf
}

// WebAuthnName returns the kid
func (k Key) WebAuthnName() string {
	return k.kid
}

// WebAuthnDisplayName returns the kid
func (k Key) WebAuthnDisplayName() string {
	return k.kid
}

// WebAuthnIcon is not (yet) implemented
func (k Key) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the key
func (k *Key) AddCredential(cred webauthn.Credential) {
	k.credentials = append(k.credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the key
func (k Key) WebAuthnCredentials() []webauthn.Credential {
	return k.credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the key's credentials
func (k Key) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range k.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
