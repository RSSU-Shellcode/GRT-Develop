package argument

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// +---------+----------+----------+-----------+----------+----------+
// |   key   | checksum | num args | args size | arg size | arg data |
// +---------+----------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32  |  uint32   |  uint32  |   var    |
// +---------+----------+----------+-----------+----------+----------+

const (
	cryptoKeySize  = 32
	offsetChecksum = 32
	offsetNumArgs  = 32 + 4
	offsetFirstArg = 32 + 4 + 4 + 4
)

// Encode is used to encode and encrypt arguments for runtime argument stub
func Encode(args [][]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buffer := bytes.NewBuffer(make([]byte, 0, offsetFirstArg))
	buffer.Write(key)
	// reserve space for checksum
	buffer.Write(make([]byte, 4))
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
	// write arguments
	for i := 0; i < len(args); i++ {
		// write argument size
		binary.LittleEndian.PutUint32(buf, uint32(len(args[i])))
		buffer.Write(buf)
		// write argument data
		buffer.Write(args[i])
	}
	output := buffer.Bytes()
	// calculate checksum
	var checksum uint32
	for _, b := range output[offsetFirstArg:] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	binary.LittleEndian.PutUint32(output[offsetChecksum:], checksum)
	encryptStub(output)
	return output, nil
}

func encryptStub(stub []byte) {
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		last = data[i]
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}

// Decode is used to decrypt and decode arguments from raw stub.
func Decode(stub []byte) ([][]byte, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("stub is too short")
	}
	numArgs := binary.LittleEndian.Uint32(stub[offsetNumArgs:])
	if numArgs == 0 {
		return nil, nil
	}
	decryptStub(stub)
	// calculate checksum
	var checksum uint32
	for _, b := range stub[offsetFirstArg:] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	expected := binary.LittleEndian.Uint32(stub[offsetChecksum:])
	if checksum != expected {
		return nil, errors.New("invalid checksum")
	}
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
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		data[i] = b
		last = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}
