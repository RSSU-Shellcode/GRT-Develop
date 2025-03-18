package serialization

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		s1 := testStruct{
			Arg1: 123,
			Arg2: [2]uint32{456, 789},
			Arg3: nil,
			Arg4: "",
			Arg5: 0x19,
			Arg6: 0x1548,
			Arg7: nil,
			Arg8: "hello",
			Arg9: []byte{0x12, 0x34},

			Arg10: 0x12,
			Arg11: 0x1234,
			Arg12: -0x12345678,
			Arg13: -0x1234567812345678,
			Arg14: 0x12,
			Arg15: 0x1234,
			Arg16: 0x12345678,
			Arg17: 0x1234567812345678,
			Arg18: 0.1234,
			Arg19: 0.123459664,
			Arg20: true,

			Arg26: [2]uint16{0x1234, 0x5678},
			Arg37: []uint16{0x5678, 0x1234},

			Arg42: []bool{true, false},

			unexported: 123,
		}
		data, err := Marshal(&s1)
		require.NoError(t, err)

		var s2 testStruct
		err = Unmarshal(data, &s2)
		require.NoError(t, err)

		s1.unexported = 0
		require.Equal(t, s1, s2)
	})
}
