package microtoken

import (
	"encoding/json"

	"errors"
)

type KidField struct {
	value string
}

func NewKidField() *KidField {
	return &KidField{}
}

func (f *KidField) EncodeMicroField() ([]byte, error) {
	switch f.value {
	case "es":
		return []byte{byte(FieldKID) | (byte(ExtendedTypeVariationsFlag) << 4)}, nil
	default:
		result := append([]byte{byte(FieldKID) | (byte(ExtendedTypeString) << 4)}, f.value...)
		result = append(result, 0)
		return result, nil
	}
}

func (f *KidField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, errors.New("microtoken: invalid field data")
	}

	if (data[0] & 0b1111) != byte(FieldKID) {
		return nil, errors.New("microtoken: invalid field type")
	}

	extendedType := ExtendedType((data[0] >> 4) & 0b1111)
	switch extendedType {
	case ExtendedTypeString:
		result, remainder := readString(data[1:])
		if remainder == nil {
			return nil, errors.New("microtoken: read string failed")
		}

		f.value = result
		return remainder, nil
	case ExtendedTypeVariationsFlag:
		f.value = "es"
		return data[1:], nil
	default:
		return nil, errors.New("microtoken: invalid field type")
	}
}

func (f *KidField) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &f.value)
}

func (f *KidField) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.value)
}

func (f *KidField) Key() string {
	return "kid"
}
