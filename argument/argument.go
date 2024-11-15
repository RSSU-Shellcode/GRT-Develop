package argument

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// +---------+----------+-----------+----------+-----------+-----------+
// |   key   | num args | args size | checksum | arg1 size | arg1 data |
// +---------+----------+-----------+----------+-----------+-----------+
// | 32 byte |  uint32  |  uint32   |  uint32  |  uint32   |    var    |
// +---------+----------+-----------+----------+-----------+-----------+

const (
	cryptoKeySize  = 32
	offsetNumArgs  = 32
	offsetChecksum = 32 + 4 + 4
	offsetFirstArg = 32 + 4 + 4 + 4
)

// Encode is used to encode and encrypt arguments to stub.
func Encode(args ...[]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buffer := bytes.NewBuffer(nil)
	buffer.Grow(offsetFirstArg)
	buffer.Write(key)
	// write the number of arguments
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(args)))
	buffer.Write(buf)
	// calculate the total size of the arguments
	var totalSize int
	for i := 0; i < len(args); i++ {
		totalSize += 4 + len(args[i])
	}
	binary.LittleEndian.PutUint32(buf, uint32(totalSize))
	buffer.Write(buf)
	// calculate checksum
	var checksum uint32
	for _, b := range buffer.Bytes() {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	binary.LittleEndian.PutUint32(buf, checksum)
	buffer.Write(buf)
	// write arguments
	for i := 0; i < len(args); i++ {
		// write argument size
		binary.LittleEndian.PutUint32(buf, uint32(len(args[i])))
		buffer.Write(buf)
		// write argument data
		buffer.Write(args[i])
	}
	output := buffer.Bytes()
	encryptStub(output)
	return output, nil
}

func encryptStub(stub []byte) {
	data := stub[offsetFirstArg:]
	key := stub[:cryptoKeySize]
	last := binary.LittleEndian.Uint64(key[:8])
	ctr := binary.LittleEndian.Uint64(key[8:])
	keyIdx := last % 32
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)
		b = rol(b, uint8(last%8))
		b ^= key[keyIdx]
		b += byte(ctr ^ last)
		b = ror(b, uint8(last%8))
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
		ctr++
		last = xorShift64(last)
	}
}

// Decode is used to decrypt and decode arguments from raw stub.
func Decode(stub []byte) ([][]byte, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("invalid argument stub")
	}
	// calculate checksum
	var checksum uint32
	for _, b := range stub[:offsetChecksum] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	expected := binary.LittleEndian.Uint32(stub[offsetChecksum:])
	if checksum != expected {
		return nil, errors.New("invalid argument stub checksum")
	}
	numArgs := binary.LittleEndian.Uint32(stub[offsetNumArgs:])
	if numArgs == 0 {
		return nil, nil
	}
	decryptStub(stub)
	// decode arguments
	args := make([][]byte, 0, numArgs)
	offset := offsetFirstArg
	for i := 0; i < int(numArgs); i++ {
		l := binary.LittleEndian.Uint32(stub[offset:])
		arg := make([]byte, l)
		copy(arg, stub[offset+4:offset+4+int(l)])
		args = append(args, arg)
		offset += 4 + int(l)
	}
	return args, nil
}

func decryptStub(stub []byte) {
	data := stub[offsetFirstArg:]
	key := stub[:cryptoKeySize]
	last := binary.LittleEndian.Uint64(key[:8])
	ctr := binary.LittleEndian.Uint64(key[8:])
	keyIdx := last % 32
	for i := 0; i < len(data); i++ {
		b := data[i]
		b = rol(b, uint8(last%8))
		b -= byte(ctr ^ last)
		b ^= key[keyIdx]
		b = ror(b, uint8(last%8))
		b ^= byte(last)
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
		ctr++
		last = xorShift64(last)
	}
}

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}
