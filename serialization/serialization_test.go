package serialization

import (
	"testing"
	
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	arg1 uint32
	arg2 [2]uint32
	arg3 []byte
	arg4 string
	arg5 uint8
	arg6 uint16
	arg7 uintptr
	arg8 string
	arg9 []byte
	
	arg10 int8
	arg11 int16
	arg12 int32
	arg13 int64
	arg14 uint8
	arg15 uint16
	arg16 uint32
	arg17 uint64
	arg18 float32
	arg19 float64
	arg20 bool
	
	arg21 [2]int8
	arg22 [2]int16
	arg23 [2]int32
	arg24 [2]int64
	arg25 [2]uint8
	arg26 [2]uint16
	arg27 [2]uint32
	arg28 [2]uint64
	arg29 [2]float32
	arg30 [2]float64
	arg31 [2]bool
	
	arg32 []int8
	arg33 []int16
	arg34 []int32
	arg35 []int64
	arg36 []uint8
	arg37 []uint16
	arg38 []uint32
	arg39 []uint64
	arg40 []float32
	arg41 []float64
	arg42 []bool
}

func TestMarshal(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		s1 := testStruct{
			arg1: 123,
			arg2: [2]uint32{456, 789},
			arg3: nil,
			arg4: "",
			arg5: 0x19,
			arg6: 0x1548,
			arg7: 0x123,
			arg8: "hello",
			arg9: []byte{0x12, 0x34},
			
			arg10: 0x12,
			arg11: 0x1234,
			arg12: -0x12345678,
			arg13: -0x1234567812345678,
			arg14: 0x12,
			arg15: 0x1234,
			arg16: 0x12345678,
			arg17: 0x1234567812345678,
			arg18: 0.1234,
			arg19: 0.123459664,
			arg20: true,
			
			arg26: [2]uint16{0x1234, 0x5678},
			arg37: []uint16{0x5678, 0x1234},
			
			arg42: []bool{true, false},
		}
		data, err := Marshal(s1)
		require.NoError(t, err)
		
		spew.Dump(data)
	})
}

func TestUnmarshal(t *testing.T) {

}
