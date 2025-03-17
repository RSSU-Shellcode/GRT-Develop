package serialization

import (
	"encoding/binary"
	"unicode/utf16"
)

// serialized data structure
// +---------+----------+----------+----------+------------+
// |  magic  |  item 1  |  item 2  | item END |  raw data  |
// +---------+----------+----------+----------+------------+
// |  uint32 |  uint32  |  uint32  |  uint32  |    var     |
// +---------+----------+----------+----------+------------+
//
// item data structure
// 0······· value or pointer
// ·0000000 data length

const (
	headerMagic = 0xFFFFFFFF
	itemEnd     = 0x00000000

	flagValue   = 0x00000000
	flagPointer = 0x80000000

	maskFlag   = 0x80000000
	maskLength = 0x7FFFFFFF
)

func stringToUTF16(s string) []byte {
	if s == "" {
		return nil
	}
	w := utf16.Encode([]rune(s))
	output := make([]byte, (len(w)+1)*2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return output
}
