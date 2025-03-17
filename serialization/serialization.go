package serialization

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf16"
	"unsafe"
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

// Serialize is used to serialize structure to binary data.
//
//gocyclo:ignore
func Serialize(v any) ([]byte, error) {
	value := reflect.ValueOf(v)
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return nil, errors.New("value is a nil pointer passed")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil, errors.New("value must be a struct or pointer to struct")
	}
	// generate descriptors and data
	var (
		descriptors []uint32
		dataList    [][]byte
	)
	num := value.NumField()
	for i := 0; i < num; i++ {
		var (
			desc uint32
			data []byte
		)
		field := value.Field(i)
		switch field.Type().Kind() {
		case reflect.Bool:
			desc = flagValue | 1
			data = make([]byte, 1)
			if field.Bool() {
				data[0] = 1
			}
		case reflect.Int8:
			desc = flagValue | 1
			data = make([]byte, 1)
			data[0] = uint8(field.Int()) // #nosec G115
		case reflect.Int16:
			desc = flagValue | 2
			data = make([]byte, 2)
			binary.LittleEndian.PutUint16(data, uint16(field.Int())) // #nosec G115
		case reflect.Int32:
			desc = flagValue | 4
			data = make([]byte, 4)
			binary.LittleEndian.PutUint32(data, uint32(field.Int())) // #nosec G115
		case reflect.Int64:
			desc = flagValue | 8
			data = make([]byte, 8)
			binary.LittleEndian.PutUint64(data, uint64(field.Int())) // #nosec G115
		case reflect.Uint8:
			desc = flagValue | 1
			data = make([]byte, 1)
			data[0] = uint8(field.Uint()) // #nosec G115
		case reflect.Uint16:
			desc = flagValue | 2
			data = make([]byte, 2)
			binary.LittleEndian.PutUint16(data, uint16(field.Uint())) // #nosec G115
		case reflect.Uint32:
			desc = flagValue | 4
			data = make([]byte, 4)
			binary.LittleEndian.PutUint32(data, uint32(field.Uint())) // #nosec G115
		case reflect.Uint64:
			desc = flagValue | 8
			data = make([]byte, 8)
			binary.LittleEndian.PutUint64(data, field.Uint())
		case reflect.Uintptr:
			desc = flagPointer
		case reflect.Float32:
			desc = flagValue | 4
			data = make([]byte, 4)
			f := float32(field.Float())
			n := *(*uint32)(unsafe.Pointer(&f)) // #nosec
			binary.LittleEndian.PutUint32(data, n)
		case reflect.Float64:
			desc = flagValue | 8
			data = make([]byte, 8)
			f := field.Float()
			n := *(*uint64)(unsafe.Pointer(&f)) // #nosec
			binary.LittleEndian.PutUint64(data, n)
		case reflect.String:
			data = stringToUTF16(field.String())
			desc = flagPointer | uint32(len(data)) // #nosec G115
		case reflect.Array:

		case reflect.Slice:

		default:
			return nil, fmt.Errorf("field type of %s is not support", field.Kind())
		}
		descriptors = append(descriptors, desc)
		dataList = append(dataList, data)
	}
	descriptors = append(descriptors, itemEnd)
	// write magic number
	var buffer []byte
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, headerMagic)
	buffer = append(buffer, buf...)
	// write descriptors
	for _, desc := range descriptors {
		binary.LittleEndian.PutUint32(buf, desc)
		buffer = append(buffer, buf...)
	}
	// write raw data
	for _, data := range dataList {
		buffer = append(buffer, data...)
	}
	return buffer, nil
}

// Unserialize is used to unserialize binary data to structure.
func Unserialize(data []byte, v any) bool {
	return true
}

func stringToUTF16(s string) []byte {
	w := utf16.Encode([]rune(s))
	output := make([]byte, (len(w)+1)*2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return output
}
