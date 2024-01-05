package microtoken

import (
	"encoding/json"

	"errors"
	"github.com/gofrs/uuid"
)

type SubjectField struct {
	id             uuid.UUID
	fallbackString string
}

func NewSubjectField() *SubjectField {
	return &SubjectField{}
}

func (f *SubjectField) EncodeMicroField() ([]byte, error) {
	if f.fallbackString != "" {
		result := append([]byte{byte(FieldSUB) | (byte(ExtendedTypeString) << 4)}, f.fallbackString...)
		result = append(result, 0)
		return result, nil
	}

	return append([]byte{byte(FieldSUB) | (byte(ExtendedTypeVariationsFlag) << 4)}, f.id.Bytes()...), nil
}

func (f *SubjectField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 17 {
		return nil, errors.New("microtoken: invalid field data")
	}

	if (data[0] & 0b1111) != byte(FieldSUB) {
		return nil, errors.New("microtoken: invalid field type")
	}

	extendedType := ExtendedType((data[0] >> 4) & 0b1111)
	switch extendedType {
	case ExtendedTypeString:
		result, remainder := readString(data[1:])
		if remainder == nil {
			return nil, errors.New("microtoken: read string failed")
		}

		f.fallbackString = result
		return remainder, nil
	case ExtendedTypeVariationsFlag:
		var err error
		f.id, err = uuid.FromBytes(data[1:17])
		if err != nil {
			return nil, err
		}

		return data[17:], nil
	default:
		return nil, errors.New("microtoken: invalid field type")
	}
}

func (f *SubjectField) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	id, err := uuid.FromString(str)
	if err != nil {
		return nil
	}

	if id.String() != str {
		f.fallbackString = str
		return nil
	}

	f.id = id
	return nil
}

func (f *SubjectField) MarshalJSON() ([]byte, error) {
	if f.fallbackString != "" {
		return json.Marshal(f.fallbackString)
	}

	return json.Marshal(f.id.String())
}

func (f *SubjectField) Key() string {
	return "sub"
}
