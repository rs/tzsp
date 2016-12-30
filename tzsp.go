//go:generate stringer -type=Type
//go:generate stringer -type=Proto
//go:generate stringer -type=TagType

// Copyright 2016 Olivier Poitrey <rs@rhapsodyk.net>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tzsp provides a basic TaZmen Sniffer Protocol parser.
package tzsp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Type defines TZSP packet type.
type Type uint8

// Proto defines TZSP encapsulated protocol.
type Proto uint16

// Header is TZSP packet header.
type Header struct {
	Version uint8
	Type    Type
	Proto   Proto
}

// TagType defines TZSP tag type.
type TagType uint8

// Tag is a TZSP packet tag.
type Tag struct {
	Type   TagType
	Length uint8
	Data   []byte
}

// Packet is a TZSP packet content.
type Packet struct {
	Header Header
	Tags   []Tag
	Data   []byte
}

const (
	// TypeReceivedTagList is received tag list.
	TypeReceivedTagList Type = iota
	// TypePacketForTransmit is packet for transmit.
	TypePacketForTransmit
	// TypeReserved is reserved.
	TypeReserved
	// TypeConfiguration is configuration.
	TypeConfiguration
	// TypeKeepAlive is Keep alive.
	TypeKeepAlive
	// TypePortOpener is Port opener.
	TypePortOpener
)

const (
	// ProtoEthernet ethernet encapsulated protocol.
	ProtoEthernet Proto = 0x01
	// ProtoIEEE80211 IEEE 802.11 encapsulated protocol.
	ProtoIEEE80211 Proto = 0x12
	// ProtoPrismHeader Prisma encapsulated protocol.
	ProtoPrismHeader Proto = 0x77
	// ProtoWLANAVS WLAN AVS encapsulated protocol.
	ProtoWLANAVS Proto = 0x7f
)

const (
	// TagPadding is a special tagged field which has neither tag length nor any tag data.
	// The receiver should ignore it. It is sometimes used to pack the frame to a word boundary.
	TagPadding TagType = 0x00
	// TagEnd is a special tagged field which has neither tag length nor any tag data.
	// This means that there are no more tags. Following this tag, until the end
	// of the UDP packet, is the encapsulated frame. This is the only tag that is
	// required and must be included before the encapsulated data. No variable tags
	// can follow this one.
	TagEnd TagType = 0x01
	// TagRawRSSI contains the raw RSSI obtained from the sensor.
	// The data is either a signed byte or signed short.
	TagRawRSSI TagType = 0x0a
	// TagSNR contains the raw noise obtained from the sensor.
	// The data is either a signed byte or signed short.
	TagSNR TagType = 0x0b
	// TagDataRate contains the data rate the encapsulated packet was transmitted at.
	TagDataRate TagType = 0x0c
	// TagTimestamp is the time the sensor MAC received the packet.
	// It is a 4-byte unsigned int.
	TagTimestamp TagType = 0xd
	// TagContentionFree is used to tell if the packet was sent in a contention free period.
	// It is a 1-byte unsigned byte.
	TagContentionFree TagType = 0x0f
	// TagDecrypted is used to tell if the packet was decrypted. It is a 1-byte unsigned byte.
	TagDecrypted TagType = 0x10
	// TagFCSError is used to tell if the packet had an frame check sequence (FCS) error in reception.
	// It is a 1-byte unsigned byte. A one (0x01) specifies that there was an FCS error
	// on the decoding of the packet. A zero (0x00), or the exclusion of this field means
	// that there was no decoding error. All other values are reserved.
	TagFCSError TagType = 0x11
	// TagRXChannel  is the channel the sensor was on when it captured the packet.
	// It is NOT the channel the packet was transmitted on. This is stored as an unsigned byte.
	TagRXChannel TagType = 0x12
	// TagPacketCount is a monotonically increasing packet count. It is stored as a four byte unsigned int.
	TagPacketCount TagType = 0x28
	// TagRXFrameLength  is the received packet length. It is not necessarily the
	// size of the transmitted packet, which may have been truncated.
	// This is stored as a two byte unsigned short.
	TagRXFrameLength TagType = 0x29
	// TagWLANRadioHDRSerial is used by some sensor vendors to specify the serial
	// number or other unique identifier for the sensor or AP that captured the packet.
	// The is a variable length field.
	TagWLANRadioHDRSerial TagType = 0x3c
)

var (
	headerLen = 4

	// ErrHeaderTooShort is returned when size of the packet is lower 4 bytes.
	ErrHeaderTooShort = errors.New("header too short")
	// ErrUnsupportedVersion is returned when the packet version is not 1.
	ErrUnsupportedVersion = errors.New("unsupported version")
	// ErrUnsupportedPacketType is returned when the packet type is not supported
	// by this package.
	ErrUnsupportedPacketType = errors.New("unsupported packet type")
	// ErrTruncatedTag is returned when an EOF is reached while parsing a tag.
	ErrTruncatedTag = errors.New("truncated tag")
	// ErrMissingEndTag is returned when the no END tag is provided.
	ErrMissingEndTag = errors.New("packet truncated (no END tag)")
)

// Parse reads a packet bytes and parse the contained TZSP packet.
func Parse(b []byte) (p Packet, err error) {
	p.Header, err = parseHeader(b)
	if err != nil {
		return
	}
	if p.Header.Version != 1 {
		return p, ErrUnsupportedVersion
	}
	if p.Header.Type != TypeReceivedTagList {
		return p, ErrUnsupportedPacketType
	}
	b = b[headerLen:]
	p.Tags = []Tag{}
	var t Tag
	for len(b) > 0 && t.Type != TagEnd {
		var l int
		t, l, err = parseTag(b)
		if err != nil {
			return
		}
		p.Tags = append(p.Tags, t)
		b = b[l:]
	}
	if t.Type != TagEnd {
		return p, ErrMissingEndTag
	}
	p.Data = b
	return
}

func parseHeader(b []byte) (h Header, err error) {
	if len(b) < headerLen {
		return h, ErrHeaderTooShort
	}
	h.Version = uint8(b[0])
	h.Type = Type(b[1])
	h.Proto = Proto(binary.BigEndian.Uint16(b[2:4]))
	return
}

func parseTag(b []byte) (t Tag, l int, err error) {
	t.Type = TagType(b[0])
	l = 1
	if t.Type == TagPadding || t.Type == TagEnd {
		// Those tags have no length nor data
		return
	}
	if len(b) < 2 {
		return t, 0, ErrTruncatedTag
	}
	t.Length = b[1]
	l = int(t.Length + 2)
	if len(b) < l {
		return t, 0, ErrTruncatedTag
	}
	t.Data = b[2:l]
	return
}

func (p Packet) String() (s string) {
	s = fmt.Sprintf("Version: %d, Type: %s, Proto: %s",
		p.Header.Version, p.Header.Type.String(), p.Header.Proto.String())
	for _, t := range p.Tags {
		s += fmt.Sprintf("\n  - Type: %s, Len: %d, Data: %v",
			t.Type.String(), t.Length, t.Data)
	}
	s += fmt.Sprintf("\n    Data: %v\n", p.Data)
	return
}
