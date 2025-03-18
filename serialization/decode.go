package serialization

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

// Unmarshal is used to unserialize binary data to structure.
func Unmarshal(data []byte, v any) error {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return errors.New("value must be a non-nil pointer")
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return errors.New("value must be a pointer to struct")
	}
	if len(data) < 8 {
		return errors.New("invalid data length")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != headerMagic {
		return errors.New("invalid magic number")
	}
	// parse descriptors and check the number of the structure fields
	var descriptors []uint32
	reader := bytes.NewReader(data[4:])
	for {
		buf := make([]byte, 4)
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		desc := binary.LittleEndian.Uint32(buf)
		if desc == itemEnd {
			break
		}
		descriptors = append(descriptors, desc)
	}
	numFields := value.NumField()
	if numFields != len(descriptors) {
		return fmt.Errorf("invalid number of struct fields: %d", value.NumField())
	}
	// process the structure value
	for i := 0; i < numFields; i++ {
		field := value.Field(i)
		desc := descriptors[i]
		flag := desc & maskFlag
		size := desc & maskLength
		switch flag {
		case flagValue:

		case flagPointer:

		default:
			return fmt.Errorf("invalid descriptor: 0x%x", desc)
		}
	}
	return nil
}

func decodeValue(field reflect.Value, reader *bytes.Reader) error {
	var (
		buf []byte
		err error
	)
	switch field.Type().Kind() {
	case reflect.Int8:
		buf = make([]byte, 1)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		field.SetInt(int64(buf[0]))
	case reflect.Int16:
		buf = make([]byte, 2)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		val := binary.LittleEndian.Uint16(buf)
		field.SetInt(int64(val))
	case reflect.Int32:
		buf = make([]byte, 4)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		val := binary.LittleEndian.Uint32(buf)
		field.SetInt(int64(val))
	case reflect.Int64:
		buf = make([]byte, 8)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		val := binary.LittleEndian.Uint64(buf)
		field.SetInt(int64(val))
	case reflect.Uint8:
		buf = make([]byte, 1)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return err
		}
		field.SetUint(uint64(buf[0]))
	case reflect.Uint16:
		desc = flagValue | 2
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(field.Uint())) // #nosec G115
	case reflect.Uint32:
		desc = flagValue | 4
		buf = make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(field.Uint())) // #nosec G115
	case reflect.Uint64:
		desc = flagValue | 8
		buf = make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, field.Uint())
	case reflect.Float32:
		desc = flagValue | 4
		buf = make([]byte, 4)
		f := float32(field.Float())
		n := *(*uint32)(unsafe.Pointer(&f)) // #nosec
		binary.LittleEndian.PutUint32(buf, n)
	case reflect.Float64:
		desc = flagValue | 8
		buf = make([]byte, 8)
		f := field.Float()
		n := *(*uint64)(unsafe.Pointer(&f)) // #nosec
		binary.LittleEndian.PutUint64(buf, n)
	case reflect.Bool:
		desc = flagValue | 1
		buf = make([]byte, 1)
		if field.Bool() {
			buf[0] = 1
		}
	default:
		return fmt.Errorf("field type of %s is not support", field.Kind())
	}
}

func decodePointer(field reflect.Value, reader *bytes.Reader) error {
	return nil
}
