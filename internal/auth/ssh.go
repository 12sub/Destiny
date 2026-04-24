package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"

	"golang.org/x/crypto/ssh"
)

func GenerateSSHKeyPair(name string) error {
	// 1. Generate the key pair
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// 2. Encode the private key to PEM
	privBytes, _ := ssh.MarshalPrivateKey(priv, "")
	privPEM := pem.EncodeToMemory(privBytes)
	os.WriteFile(name+".key", privPEM, 0600)

	// 3. Encode Public key
	publicKey, _ := ssh.NewPublicKey(pub)
	pubBytes := ssh.MarshalAuthorizedKey(publicKey)
	os.WriteFile(name+".pub", pubBytes, 0644)

	return nil
}