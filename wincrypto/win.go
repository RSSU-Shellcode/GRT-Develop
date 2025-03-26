package wincrypto

// reference:
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
// https://learn.microsoft.com/en-us/windows/win32/seccrypto/rsa-schannel-key-blobs

const (
	curBlobVersion = 0x02

	cAlgRSASign = 0x00002400
	cAlgRSAKeyX = 0x0000A400

	publicKeyBlob  = 0x06
	privateKeyBlob = 0x07

	magicRSA1 = 0x31415352
	magicRSA2 = 0x32415352
)

var (
	_ rsaPublicKey
	_ rsaPrivateKey
)

//nolint:unused
type blobHeader struct {
	Type     byte
	Version  byte
	Reserved uint16
	AiKeyAlg uint32
}

//nolint:unused
type rsaPubKey struct {
	Magic  uint32
	BitLen uint32
	PubExp uint32
}

//nolint:unused
type rsaPublicKey struct {
	header    blobHeader
	rsaPubKey rsaPubKey
	modulus   []byte
}

//nolint:unused
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
