package wincrypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
)

// reference:
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/rsa-schannel-key-blobs

type blobHeader struct {
	bType    byte
	bVersion byte
	reserved uint16
	aiKeyAlg uint32
}

type rsaPubKey struct {
	magic  uint32
	bitLen uint32
	pubExp uint32
}

type rsaPublicKey struct {
	header    blobHeader
	rsaPubKey rsaPubKey
	modulus   []byte
}

type rsaPrivateKey struct {
	header      blobHeader
	rsaPubKey   rsaPubKey
	modulus     []byte
	prime1      []byte
	prime2      []byte
	exponent1   []byte
	exponent2   []byte
	coefficient []byte
	priExponent []byte
}

var (
	_ rsaPublicKey
	_ rsaPrivateKey
)

const (
	curBlobVersion = 0x02

	cAlgRSASign = 0x00002400
	cAlgRSAKeyX = 0x0000A400

	publicKeyBlob  = 0x06
	privateKeyBlob = 0x07

	magicRSA1 = 0x31415352
	magicRSA2 = 0x32415352
)

// about RSA key usage.
const (
	RSAKeyUsageSIGN = 1
	RSAKeyUsageKEYX = 2
)

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
func ExportRSAPrivateKeyBlob(key *rsa.PrivateKey, usage int) ([]byte, error) {
	switch usage {
	case RSAKeyUsageSIGN:
	case RSAKeyUsageKEYX:
	default:
		return nil, errors.New("invalid rsa key usage")
	}
	return nil, nil
}

// ExportRSAPublicKeyBlob is used to export rsa public key with PublicKeyBlob.
func ExportRSAPublicKeyBlob(key *rsa.PublicKey, usage int) ([]byte, error) {
	var ku uint32
	switch usage {
	case RSAKeyUsageSIGN:
		ku = cAlgRSASign
	case RSAKeyUsageKEYX:
		ku = cAlgRSAKeyX
	default:
		return nil, errors.New("invalid rsa key usage")
	}
	buffer := bytes.NewBuffer(make([]byte, 0, key.Size()*4))
	// write blob header
	buffer.WriteByte(publicKeyBlob)
	buffer.WriteByte(curBlobVersion)
	buffer.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(buffer, binary.LittleEndian, ku)
	// write rsaPubKey
	_ = binary.Write(buffer, binary.LittleEndian, uint32(magicRSA1))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.Size()*8))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.E))
	// write modulus
	buf := make([]byte, key.Size())
	buf = key.N.FillBytes(buf)
	buffer.Write(reverseBytes(buf))
	return buffer.Bytes(), nil
}

func reverseBytes(b []byte) []byte {
	n := len(b)
	r := make([]byte, n)
	for i := 0; i < n; i++ {
		r[i] = b[n-1-i]
	}
	return r
}
