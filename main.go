package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

type ECDSASignature struct {
	r *big.Int
	s *big.Int
}

func generateKeys() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func hashMessage(message string) []byte {
	hash := sha256.Sum256([]byte(message))
	return hash[:]
}

func sign(privateKey *ecdsa.PrivateKey, message []byte) (*ECDSASignature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, message)
	if err != nil {
		return nil, err
	}
	return &ECDSASignature{r, s}, nil
}

func verify(publicKey *ecdsa.PublicKey, signature *ECDSASignature, message []byte) bool {
	return ecdsa.Verify(publicKey, message, signature.r, signature.s)
}

func serializePublicKey(publicKey *ecdsa.PublicKey) string {
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	return hex.EncodeToString(xBytes) + "," + hex.EncodeToString(yBytes)
}

func serializePrivateKey(privateKey *ecdsa.PrivateKey) string {
	return hex.EncodeToString(privateKey.D.Bytes())
}
func serializeSignature(signature *ECDSASignature) string {
	return hex.EncodeToString(signature.r.Bytes()) + "," + hex.EncodeToString(signature.s.Bytes())
}
func deserializePublicKey(keyStr string) (*ecdsa.PublicKey, error) {
	xy := strings.Split(keyStr, ",")
	if len(xy) != 2 {
		return nil, fmt.Errorf("invalid public key format")
	}
	x, err := hex.DecodeString(xy[0])
	if err != nil {
		return nil, err
	}
	y, err := hex.DecodeString(xy[1])
	if err != nil {
		return nil, err
	}
	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P256()
	publicKey.X, publicKey.Y = new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
	return publicKey, nil
}

func deserializePrivateKey(keyStr string) (*ecdsa.PrivateKey, error) {
	d, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: new(big.Int).SetBytes(d)}, nil
}

func deserializeSignature(signatureStr string) (*ECDSASignature, error) {
	rs := strings.Split(signatureStr, ",")
	if len(rs) != 2 {
		return nil, fmt.Errorf("invalid signature format")
	}
	r, err := hex.DecodeString(rs[0])
	if err != nil {
		return nil, err
	}
	s, err := hex.DecodeString(rs[1])
	if err != nil {
		return nil, err
	}
	return &ECDSASignature{r: new(big.Int).SetBytes(r), s: new(big.Int).SetBytes(s)}, nil
}

func main() {
	message := "Hello, world!"

	// Generating keys
	privateKey, err := generateKeys()
	if err != nil {
		panic(err)
	}

	// Hashing message
	hashedMessage := hashMessage(message)

	// Signing message
	signature, err := sign(privateKey, hashedMessage)
	if err != nil {
		panic(err)
	}

	// Verifying signature
	publicKey := &privateKey.PublicKey
	isValid := verify(publicKey, signature, hashedMessage)
	if isValid {
		fmt.Println("Signature is valid!")
	} else {
		fmt.Println("Signature is not valid!")
	}

	// Serialization and deserialization examples
	serializedPublicKey := serializePublicKey(publicKey)
	serializedPrivateKey := serializePrivateKey(privateKey)
	serializedSignature := serializeSignature(signature)

	fmt.Println("Serialized Public Key:", serializedPublicKey)
	fmt.Println("Serialized Private Key:", serializedPrivateKey)
	fmt.Println("Serialized Signature:", serializedSignature)

	deserializedPublicKey, err := deserializePublicKey(serializedPublicKey)
	if err != nil {
		panic(err)
	}

	deserializedPrivateKey, err := deserializePrivateKey(serializedPrivateKey)
	if err != nil {
		panic(err)
	}

	deserializedSignature, err := deserializeSignature(serializedSignature)
	if err != nil {
		panic(err)
	}

	fmt.Println("Deserialized Public Key:", deserializedPublicKey)
	fmt.Println("Deserialized Private Key:", deserializedPrivateKey)
	fmt.Println("Deserialized Signature:", deserializedSignature)
}
