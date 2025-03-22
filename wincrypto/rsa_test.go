package wincrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestParseRSAPublicKeyPEM(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		})

		pub, err := ParseRSAPublicKeyPEM(data)
		require.NoError(t, err)
		require.Equal(t, &key.PublicKey, pub)
	})

	t.Run("invalid data", func(t *testing.T) {
		pub, err := ParseRSAPublicKeyPEM(nil)
		require.EqualError(t, err, "failed to decode PEM data")
		require.Nil(t, pub)
	})
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		pri, err := ParseRSAPrivateKeyPEM(data)
		require.NoError(t, err)
		require.Equal(t, key, pri)
	})

	t.Run("invalid data", func(t *testing.T) {
		pri, err := ParseRSAPrivateKeyPEM(nil)
		require.EqualError(t, err, "failed to decode PEM data")
		require.Nil(t, pri)
	})
}

func TestParseRSAPublicKey(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)

		pub, err := ParseRSAPublicKey(data)
		require.NoError(t, err)
		require.Equal(t, &key.PublicKey, pub)
	})

	t.Run("invalid data", func(t *testing.T) {
		pub, err := ParseRSAPublicKey(nil)
		require.EqualError(t, err, "asn1: syntax error: sequence truncated")
		require.Nil(t, pub)
	})

	t.Run("invalid public key type", func(t *testing.T) {
		key, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data, err := x509.MarshalPKIXPublicKey(key)
		require.NoError(t, err)

		pub, err := ParseRSAPublicKey(data)
		require.EqualError(t, err, "invalid public key type")
		require.Nil(t, pub)
	})
}

func TestParseRSAPrivateKey(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		data, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		pri, err := ParseRSAPrivateKey(data)
		require.NoError(t, err)
		require.Equal(t, key, pri)
	})

	t.Run("invalid data", func(t *testing.T) {
		pri, err := ParseRSAPrivateKey(nil)
		require.EqualError(t, err, "asn1: syntax error: sequence truncated")
		require.Nil(t, pri)
	})

	t.Run("invalid public key type", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		data, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		pri, err := ParseRSAPrivateKey(data)
		require.EqualError(t, err, "invalid private key type")
		require.Nil(t, pri)
	})
}

func TestExportRSAPublicKeyBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("sign", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, RSAKeyUsageSIGN)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 276)
	})

	t.Run("key exchange", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, RSAKeyUsageKEYX)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 276)
	})

	t.Run("invalid key usage", func(t *testing.T) {
		blob, err := ExportRSAPublicKeyBlob(&key.PublicKey, 0)
		require.EqualError(t, err, "invalid rsa key usage")
		require.Nil(t, blob)
	})
}

func TestExportRSAPrivateKeyBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("sign", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, RSAKeyUsageSIGN)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 1172)
	})

	t.Run("key exchange", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, RSAKeyUsageKEYX)
		require.NoError(t, err)

		spew.Dump(blob)
		require.Len(t, blob, 1172)
	})

	t.Run("invalid key usage", func(t *testing.T) {
		blob, err := ExportRSAPrivateKeyBlob(key, 0)
		require.EqualError(t, err, "invalid rsa key usage")
		require.Nil(t, blob)
	})
}
