package tzsp

import (
	"reflect"
	"testing"
)

func TestRead(t *testing.T) {
	tests := []struct {
		name   string
		in     []byte
		err    error
		result Packet
	}{
		{
			"valid packet",
			[]byte{0x1, 0x0, 0x0, 0x1, 0x0a, 0x1, 0x2, 0x1, 0x01, 0x02, 0x03},
			nil,
			Packet{
				Header: Header{Version: 1, Type: TypeReceivedTagList, Proto: ProtoEthernet},
				Tags: []Tag{
					{Type: TagRawRSSI, Length: 1, Data: []byte{0x2}},
					{Type: TagEnd, Length: 0, Data: []byte(nil)},
				},
				Data: []uint8{0x01, 0x02, 0x03},
			},
		},
		{
			"truncated header",
			[]byte{0x1, 0x0, 0x0},
			ErrHeaderTooShort,
			Packet{},
		},
		{
			"invalid version",
			[]byte{0x0, 0x0, 0x0, 0x1, 0x1, 0x01, 0x02, 0x03},
			ErrUnsupportedVersion,
			Packet{
				Header: Header{Version: 0, Type: TypeReceivedTagList, Proto: ProtoEthernet},
			},
		},
		{
			"unsupported packet type",
			[]byte{0x1, 0x1, 0x0, 0x1, 0x1, 0x01, 0x02, 0x03},
			ErrUnsupportedPacketType,
			Packet{
				Header: Header{Version: 1, Type: TypePacketForTransmit, Proto: ProtoEthernet},
			},
		},
		{
			"truncated tag",
			[]byte{0x1, 0x0, 0x0, 0x1, 0x02},
			ErrTruncatedTag,
			Packet{
				Header: Header{Version: 1, Type: TypeReceivedTagList, Proto: ProtoEthernet},
				Tags:   []Tag{},
			},
		},
		{
			"truncated tag length",
			[]byte{0x1, 0x0, 0x0, 0x1, 0xa, 0x1},
			ErrTruncatedTag,
			Packet{
				Header: Header{Version: 1, Type: TypeReceivedTagList, Proto: ProtoEthernet},
				Tags:   []Tag{},
			},
		},
		{
			"missing end tag",
			[]byte{0x1, 0x0, 0x0, 0x1, 0x0},
			ErrMissingEndTag,
			Packet{
				Header: Header{Version: 1, Type: TypeReceivedTagList, Proto: ProtoEthernet},
				Tags:   []Tag{{Type: TagPadding}},
			},
		},
	}
	for _, tt := range tests {
		if got, err := Read(tt.in); err != tt.err {
			t.Errorf("Failed %s\ngot err %#v, \nwant %#v", tt.name, err, tt.err)
		} else if !reflect.DeepEqual(got, tt.result) {
			t.Errorf("Failed %s\ngot  %#v, \nwant %#v", tt.name, got, tt.result)
		}
	}
}

// []byte{0x1, 0x0, 0x0, 0x1, 0x1, 0xd4, 0xca, 0x6d, 0x1d, 0x36, 0xff, 0xf4, 0xf5, 0xd8, 0xa6, 0x7e, 0x4, 0x8, 0x0, 0x45, 0x0, 0x0, 0x34, 0xfa, 0xc, 0x40, 0x0, 0x40, 0x6, 0x9b, 0x89, 0xa, 0x0, 0x0, 0x25, 0xd8, 0x3a, 0xc2, 0xce, 0x8e, 0x25, 0x1, 0xbb, 0x82, 0xb2, 0xc1, 0x8d, 0x59, 0xf3, 0x78, 0x5e, 0x80, 0x10, 0x1, 0xef, 0x6c, 0xcd, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x0, 0x57, 0x7b, 0x51, 0xac, 0x31, 0x94, 0x86}
// Version: 1, Type: TypeReceivedTagList, Proto: ProtoEthernet
//   - Type: TagEnd, Len: 0, Data: []
//     Data: [212 202 109 29 54 255 244 245 216 166 126 4 8 0 69 0 0 52 250 12 64 0 64 6 155 137 10 0 0 37 216 58 194 206 142 37 1 187 130 178 193 141 89 243 120 94 128 16 1 239 108 205 0 0 1 1 8 10 0 87 123 81 172 49 148 134]
