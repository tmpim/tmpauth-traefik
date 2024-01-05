package microtoken

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"errors"
)

type TimestampField struct {
	fieldType      FieldType
	timestamp      int64
	numberFallback float64
}

func NewTimestampField(fieldType FieldType) *TimestampField {
	return &TimestampField{
		fieldType: fieldType,
	}
}

func (f *TimestampField) EncodeMicroField() ([]byte, error) {
	var result []byte
	switch f.fieldType {
	case FieldIAT, FieldEXP, FieldNBF:
		result = append(result, byte(f.fieldType))
	default:
		return nil, fmt.Errorf("microtoken: invalid field type: %v", f.fieldType)
	}

	if (f.timestamp >= (1 << (32 + 3))) || (f.timestamp < 0) {
		f.numberFallback = float64(f.timestamp)
		f.timestamp = 0
	}

	if f.timestamp == 0 && f.numberFallback != 0 {
		// special case, fallback number
		result[0] |= (byte(ExtendedTypeNumber) << 4)
		result = binary.LittleEndian.AppendUint64(result, math.Float64bits(f.numberFallback))
		return result, nil
	}

	result[0] |= (byte(ExtendedTypeVariationsFlag) << 4) | (byte(f.timestamp>>32) << 4) // take the upper 3 bits
	result = binary.LittleEndian.AppendUint32(result, uint32(f.timestamp&0xFFFFFFFF))
	return result, nil
}

func (f *TimestampField) DecodeMicroField(data []byte) ([]byte, error) {
	f.timestamp = 0
	f.numberFallback = 0

	if len(data) < 5 {
		return nil, errors.New("microtoken: invalid field data")
	}

	f.fieldType = FieldType(data[0] & 0b1111)
	switch f.fieldType {
	case FieldIAT, FieldEXP, FieldNBF:
	default:
		return nil, fmt.Errorf("microtoken: invalid field type: %v", f.fieldType)
	}

	extendedType := ExtendedType(data[0] >> 4)
	if extendedType&ExtendedTypeNumber != 0 {
		if len(data) < 9 {
			return nil, errors.New("microtoken: field is type number, but data is too short")
		}

		f.numberFallback = math.Float64frombits(binary.LittleEndian.Uint64(data[1:9]))
		return data[9:], nil
	}

	if extendedType&ExtendedTypeVariationsFlag != 0 {
		f.timestamp = int64(extendedType&0b111) << 32
		f.timestamp |= int64(binary.LittleEndian.Uint32(data[1:5]))
		return data[5:], nil
	}

	return nil, fmt.Errorf("microtoken: invalid extended type: %v", extendedType)
}

func (f *TimestampField) UnmarshalJSON(data []byte) error {
	f.timestamp = 0
	f.numberFallback = 0

	var timestamp int64
	err := json.Unmarshal(data, &timestamp)
	if err != nil {
		var number float64
		err = json.Unmarshal(data, &number)
		if err != nil {
			return err
		}

		f.numberFallback = number
		return nil
	}

	f.timestamp = timestamp
	return nil
}

func (f *TimestampField) MarshalJSON() ([]byte, error) {
	if f.timestamp == 0 && f.numberFallback != 0 {
		return json.Marshal(f.numberFallback)
	}

	return json.Marshal(f.timestamp)
}

func (f *TimestampField) Key() string {
	switch f.fieldType {
	case FieldIAT:
		return "iat"
	case FieldEXP:
		return "exp"
	case FieldNBF:
		return "nbf"
	default:
		return ""
	}
}
