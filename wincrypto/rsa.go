package wincrypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
)

// about RSA key usage.
const (
	RSAKeyUsageSIGN = 1
	RSAKeyUsageKEYX = 2
)

// ParseRSAPublicKeyPEM is used to load rsa public key from PEM block.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	der, _ := pem.Decode(data)
	if der == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	return ParseRSAPublicKey(der.Bytes)
}

// ParseRSAPrivateKeyPEM is used to load rsa private key from PEM block.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	der, _ := pem.Decode(data)
	if der == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	return ParseRSAPrivateKey(der.Bytes)
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
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	default:
		return nil, errors.New("invalid public key type")
	}
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
	switch k := key8.(type) {
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("invalid private key type")
	}
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
	buffer := bytes.NewBuffer(make([]byte, 0, key.Size()))
	// write blob header
	buffer.WriteByte(publicKeyBlob)
	buffer.WriteByte(curBlobVersion)
	buffer.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(buffer, binary.LittleEndian, ku)
	// write rsaPubKey
	_ = binary.Write(buffer, binary.LittleEndian, uint32(magicRSA1))    // #nosec G115
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.Size()*8)) // #nosec G115
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.E))        // #nosec G115
	// write modulus
	buf := make([]byte, key.Size())
	buf = key.N.FillBytes(buf)
	buffer.Write(reverseBytes(buf))
	return buffer.Bytes(), nil
}

// ExportRSAPrivateKeyBlob is used to export rsa private key with PrivateKeyBlob.
func ExportRSAPrivateKeyBlob(key *rsa.PrivateKey, usage int) ([]byte, error) {
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
	buffer.WriteByte(privateKeyBlob)
	buffer.WriteByte(curBlobVersion)
	buffer.Write([]byte{0x00, 0x00}) // reserved
	_ = binary.Write(buffer, binary.LittleEndian, ku)
	// write rsaPubKey
	_ = binary.Write(buffer, binary.LittleEndian, uint32(magicRSA2))    // #nosec G115
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.Size()*8)) // #nosec G115
	_ = binary.Write(buffer, binary.LittleEndian, uint32(key.E))        // #nosec G115
	// prepare function for encode big int with little endian
	writeBigInt := func(i *big.Int, len int) {
		buf := make([]byte, len)
		buf = i.FillBytes(buf)
		buffer.Write(reverseBytes(buf))
	}
	keyLen := key.Size()
	// write public modulus
	writeBigInt(key.N, keyLen)
	// write P, Q
	writeBigInt(key.Primes[0], keyLen/2)
	writeBigInt(key.Primes[1], keyLen/2)
	// exponent1 = d mod (P-1)
	pMinus1 := new(big.Int).Sub(key.Primes[0], big.NewInt(1))
	exponent1 := new(big.Int).Mod(key.D, pMinus1)
	writeBigInt(exponent1, keyLen/2)
	// exponent2 = d mod (Q-1)
	qMinus1 := new(big.Int).Sub(key.Primes[1], big.NewInt(1))
	exponent2 := new(big.Int).Mod(key.D, qMinus1)
	writeBigInt(exponent2, keyLen/2)
	// coefficient = Q^-1 mod P
	coefficient := new(big.Int).ModInverse(key.Primes[1], key.Primes[0])
	writeBigInt(coefficient, keyLen/2)
	// privateExponent d
	writeBigInt(key.D, keyLen)
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
