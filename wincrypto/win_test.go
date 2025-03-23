package wincrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestWinAES(t *testing.T) {
	t.Run("encrypt", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		key := []byte{
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		}
		output, err := AESEncrypt(data, key)
		require.NoError(t, err)

		// this output will move to the test of Gleam-RT
		spew.Dump(output)
	})

	t.Run("decrypt", func(t *testing.T) {
		data := []byte{
			0x49, 0x8E, 0xD4, 0x85, 0x40, 0x12, 0x18, 0x74,
			0xDB, 0x3D, 0x2E, 0xEB, 0xA2, 0x10, 0xED, 0x9D,
			0xE9, 0xFB, 0xDF, 0x90, 0xA6, 0xB4, 0x39, 0x4A,
			0xA3, 0x62, 0xE0, 0x86, 0x1F, 0x94, 0xF7, 0xD5,
		}
		key := []byte{
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		}
		output, err := AESDecrypt(data, key)
		require.NoError(t, err)

		expected := []byte{1, 2, 3, 4}
		require.Equal(t, expected, output)
	})
}

func TestWinRSA(t *testing.T) {
	t.Run("sign", func(t *testing.T) {
		key, err := os.ReadFile("testdata/privatekey.sign")
		require.NoError(t, err)

		privateKey, err := ImportRSAPrivateKeyBlob(key)
		require.NoError(t, err)

		message := []byte{1, 2, 3, 4}
		digest := sha256.Sum256(message)

		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
		require.NoError(t, err)

		// this output will move to the test of Gleam-RT
		spew.Dump(signature)
	})

	t.Run("verify", func(t *testing.T) {

	})

	t.Run("encrypt", func(t *testing.T) {

	})

	t.Run("decrypt", func(t *testing.T) {

	})
}
