package microtoken

import (
	"encoding/json"
	"fmt"
	"strings"

	"errors"
)

type OriginSegment byte

const (
	SegmentIgnore = OriginSegment(0)

	FirstSegmentServer = OriginSegment(iota + 1)
	FirstSegmentCentral
	FirstSegmentDistributed

	TypeSegmentIdentity = OriginSegment(iota + 1)
	TypeSegmentCookie
	TypeSegmentClientID
)

type OriginField struct {
	fieldType      FieldType
	segments       []OriginSegment
	authDomain     string
	clientID       string
	fallbackString string
}

func NewOriginField(filedType FieldType, clientID string, authDomain string) *OriginField {
	return &OriginField{
		fieldType:  filedType,
		clientID:   clientID,
		authDomain: authDomain,
	}
}

func (f *OriginField) EncodeMicroField() ([]byte, error) {
	var result []byte
	switch f.fieldType {
	case FieldAUD, FieldISS:
		result = append(result, byte(f.fieldType))
	default:
		return nil, fmt.Errorf("microtoken: invalid field type: %v", f.fieldType)
	}

	if f.fallbackString != "" {
		result[0] |= (byte(ExtendedTypeString) << 4)
		result = append(result, f.fallbackString...)
		result = append(result, 0)
		return result, nil
	}

	if len(f.segments) == 0 {
		return nil, errors.New("microtoken: invalid field data")
	}

	result[0] |= (byte(ExtendedTypeVariationsFlag) << 4) | (byte(f.segments[0]) << 4)
	switch len(f.segments) {
	case 2:
		result = append(result, byte(f.segments[1]))
	case 3:
		result = append(result, byte(f.segments[1])|byte(f.segments[2]<<4))
	default:
		result = append(result, 0)
	}

	return result, nil
}

func (f *OriginField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("microtoken: invalid field data")
	}

	f.fieldType = FieldType(data[0] & 0b1111)
	switch f.fieldType {
	case FieldAUD, FieldISS:
	default:
		return nil, fmt.Errorf("microtoken: invalid field type: %v", f.fieldType)
	}

	extendedType := ExtendedType(data[0] >> 4)
	if extendedType == ExtendedTypeString {
		var remainder []byte
		f.fallbackString, remainder = readString(data[1:])
		if remainder == nil {
			return nil, errors.New("microtoken: read string failed")
		}
		return remainder, nil
	}

	if extendedType&ExtendedTypeVariationsFlag == 0 {
		return nil, errors.New("microtoken: invalid field data")
	}

	firstSegment := OriginSegment(extendedType & 0b111)
	switch firstSegment {
	case FirstSegmentServer, FirstSegmentCentral, FirstSegmentDistributed:
	default:
		return nil, fmt.Errorf("microtoken: invalid field data: %v", firstSegment)
	}

	f.segments = append(f.segments, firstSegment)

	secondSegment := OriginSegment(data[1] & 0b1111)
	switch secondSegment {
	case TypeSegmentIdentity, TypeSegmentCookie, TypeSegmentClientID:
		f.segments = append(f.segments, secondSegment)
	case SegmentIgnore:
		return data[2:], nil
	default:
		return nil, fmt.Errorf("microtoken: invalid field data: %v", secondSegment)
	}

	thirdSegment := OriginSegment(data[1] >> 4)
	switch thirdSegment {
	case TypeSegmentIdentity, TypeSegmentCookie, TypeSegmentClientID:
		f.segments = append(f.segments, thirdSegment)
	case SegmentIgnore:
	default:
		return nil, fmt.Errorf("microtoken: invalid field data: %v", secondSegment)
	}

	return data[2:], nil
}

func (f *OriginField) UnmarshalJSON(data []byte) error {
	f.segments = nil
	f.fallbackString = ""

	var origin string
	err := json.Unmarshal(data, &origin)
	if err != nil {
		return err
	}

	allSegments := strings.Split(origin, ":")
	if len(allSegments) < 2 {
		f.fallbackString = origin
		return nil
	}

	if allSegments[0] != f.authDomain {
		f.fallbackString = origin
		return nil
	}

	switch allSegments[1] {
	case "server":
		f.segments = append(f.segments, FirstSegmentServer)
	case "central":
		f.segments = append(f.segments, FirstSegmentCentral)
	case "distributed":
		f.segments = append(f.segments, FirstSegmentDistributed)
	default:
		f.fallbackString = origin
		f.segments = nil
		return nil
	}

	for _, segment := range allSegments[2:] {
		switch segment {
		case "identity":
			f.segments = append(f.segments, TypeSegmentIdentity)
		case "user_cookie":
			f.segments = append(f.segments, TypeSegmentCookie)
		default:
			if segment == f.clientID {
				f.segments = append(f.segments, TypeSegmentClientID)
			} else {
				f.fallbackString = origin
				f.segments = nil
				return nil
			}
		}
	}

	return nil
}

func (f *OriginField) MarshalJSON() ([]byte, error) {
	if f.fallbackString != "" {
		return json.Marshal(f.fallbackString)
	}

	if len(f.segments) == 0 {
		return json.Marshal("")
	}

	var result strings.Builder
	result.WriteString(f.authDomain)
	result.WriteByte(':')
	switch f.segments[0] {
	case FirstSegmentServer:
		result.WriteString("server")
	case FirstSegmentCentral:
		result.WriteString("central")
	case FirstSegmentDistributed:
		result.WriteString("distributed")
	default:
		return nil, fmt.Errorf("microtoken: invalid segment: %v", f.segments[0])
	}

	for _, segment := range f.segments[1:] {
		result.WriteByte(':')
		switch segment {
		case TypeSegmentIdentity:
			result.WriteString("identity")
		case TypeSegmentCookie:
			result.WriteString("user_cookie")
		case TypeSegmentClientID:
			result.WriteString(f.clientID)
		default:
			return nil, fmt.Errorf("microtoken: invalid segment: %v", segment)
		}
	}

	return json.Marshal(result.String())
}

func (f *OriginField) Key() string {
	switch f.fieldType {
	case FieldAUD:
		return "aud"
	case FieldISS:
		return "iss"
	default:
		return ""
	}
}
