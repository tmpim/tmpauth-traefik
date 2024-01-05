package microtoken

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"errors"
)

type GenericField struct {
	key   string
	value json.RawMessage
}

func NewGenericField(key string) *GenericField {
	return &GenericField{
		key: key,
	}
}

func (f *GenericField) EncodeMicroField() ([]byte, error) {
	var value interface{}
	var result []byte

	if err := json.Unmarshal(f.value, &value); err != nil {
		return nil, err
	}

	switch v := value.(type) {
	case string:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeString)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		result = append(result, v...)
	case float64:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeNumber)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		result = binary.LittleEndian.AppendUint64(result, math.Float64bits(v))
	case int64:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeNumber)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		result = binary.LittleEndian.AppendUint64(result, math.Float64bits(float64(v)))
	case int:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeNumber)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		result = binary.LittleEndian.AppendUint64(result, math.Float64bits(float64(v)))
	case bool:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeBool)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		if v {
			result = append(result, 1)
		} else {
			result = append(result, 0)
		}
	default:
		result = append(result, byte(FieldCustom)|(byte(ExtendedTypeRawJSON)<<4))
		result = append(result, f.key...)
		result = append(result, 0)
		result = append(result, f.value...)
		result = append(result, 0)
	}

	return result, nil
}

func (f *GenericField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, errors.New("microtoken: invalid field data")
	}

	fieldType := FieldType(data[0] & 0b1111)
	if fieldType != FieldCustom {
		return nil, fmt.Errorf("microtoken: invalid field type: %v", fieldType)
	}

	extendedType := ExtendedType(data[0] >> 4)

	f.key, data = readString(data[1:])
	if data == nil {
		return nil, errors.New("microtoken: read string failed")
	}

	var value interface{}

	switch extendedType {
	case ExtendedTypeString:
		value, data = readString(data)
		if data == nil {
			return nil, errors.New("microtoken: read string failed")
		}
	case ExtendedTypeNumber:
		if len(data) < 8 {
			return nil, errors.New("microtoken: invalid field data")
		}

		value = math.Float64frombits(binary.LittleEndian.Uint64(data))
		data = data[8:]
	case ExtendedTypeBool:
		if len(data) < 1 {
			return nil, errors.New("microtoken: invalid field data")
		}

		value = data[0] != 0
		data = data[1:]
	case ExtendedTypeRawJSON:
		value, data = readString(data)
		if data == nil {
			return nil, errors.New("microtoken: read string failed")
		}
	default:
		return nil, fmt.Errorf("microtoken: invalid extended type: %v", extendedType)
	}

	rawValue, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	f.value = json.RawMessage(rawValue)

	return data, nil

}

func (f *GenericField) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &f.value)
}

func (f *GenericField) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.value)
}

func (f *GenericField) Key() string {
	return f.key
}
