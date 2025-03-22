package wincrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// reference:
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/rsa-schannel-key-blobs

type BlobHeader struct {
	bType    byte
	bVersion byte
	reserved uint16
	aiKeyAlg uint32
}

type RSAPubKey struct {
	magic  uint32
	bitLen uint32
	pubExp uint32
}

type RSAPublicKey struct {
	header    BlobHeader
	rsaPubKey RSAPubKey
	modulus   []byte
}

type RSAPrivateKey struct {
	header      BlobHeader
	rsaPubKey   RSAPubKey
	modulus     []byte
	prime1      []byte
	prime2      []byte
	exponent1   []byte
	exponent2   []byte
	coefficient []byte
	priExponent []byte
}

// ParseRSAPrivateKeyPEM is used to load rsa private key from PEM block.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	der, _ := pem.Decode(data)
	if der == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	return ParseRSAPrivateKey(der.Bytes)
}

// ParseRSAPublicKeyPEM is used to load rsa public key from PEM block.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	der, _ := pem.Decode(data)
	if der == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	return ParseRSAPublicKey(der.Bytes)
}

// ParseRSAPrivateKey is used to load rsa private key from ASN.1 DER data.
func ParseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	key1, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return key1, nil
	}
	key8, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	switch key8.(type) {
	case *rsa.PrivateKey:
		return key8.(*rsa.PrivateKey), nil
	default:
		return nil, errors.New("invalid private key type")
	}
}

// ParseRSAPublicKey is used to load rsa public key from ASN.1 DER data.
func ParseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	key1, err := x509.ParsePKCS1PublicKey(der)
	if err == nil {
		return key1, nil
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PublicKey:
		return key.(*rsa.PublicKey), nil
	default:
		return nil, errors.New("invalid public key type")
	}
}

// ExportRSAPrivateKeyBlob is used to export rsa private key with PrivateKeyBlob.
func ExportRSAPrivateKeyBlob(key *rsa.PrivateKey) []byte {
	return nil
}

// ExportRSAPublicKeyBlob is used to export rsa public key with PublicKeyBlob.
func ExportRSAPublicKeyBlob(key *rsa.PublicKey) []byte {
	return nil
}
