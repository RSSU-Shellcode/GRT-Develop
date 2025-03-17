package serialization

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

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
