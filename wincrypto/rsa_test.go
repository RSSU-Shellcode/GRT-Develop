package wincrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

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
}
