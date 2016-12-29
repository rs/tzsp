// Code generated by "stringer -type=TagType"; DO NOT EDIT

package tzsp

import "fmt"

const (
	_TagType_name_0 = "TagPaddingTagEnd"
	_TagType_name_1 = "TagRawRSSITagSNRTagDataRateTagTimestamp"
	_TagType_name_2 = "TagContentionFreeTagDecryptedTagFCSErrorTagRXChannel"
	_TagType_name_3 = "TagPacketCountTagRXFrameLength"
	_TagType_name_4 = "TagWLANRadioHDRSerial"
)

var (
	_TagType_index_0 = [...]uint8{0, 10, 16}
	_TagType_index_1 = [...]uint8{0, 10, 16, 27, 39}
	_TagType_index_2 = [...]uint8{0, 17, 29, 40, 52}
	_TagType_index_3 = [...]uint8{0, 14, 30}
	_TagType_index_4 = [...]uint8{0, 21}
)

func (i TagType) String() string {
	switch {
	case 0 <= i && i <= 1:
		return _TagType_name_0[_TagType_index_0[i]:_TagType_index_0[i+1]]
	case 10 <= i && i <= 13:
		i -= 10
		return _TagType_name_1[_TagType_index_1[i]:_TagType_index_1[i+1]]
	case 15 <= i && i <= 18:
		i -= 15
		return _TagType_name_2[_TagType_index_2[i]:_TagType_index_2[i+1]]
	case 40 <= i && i <= 41:
		i -= 40
		return _TagType_name_3[_TagType_index_3[i]:_TagType_index_3[i+1]]
	case i == 60:
		return _TagType_name_4
	default:
		return fmt.Sprintf("TagType(%d)", i)
	}
}
