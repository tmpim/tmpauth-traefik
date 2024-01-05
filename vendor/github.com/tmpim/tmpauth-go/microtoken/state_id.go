package microtoken

import (
	"encoding/json"

	"errors"
)

type StateIDField struct {
	value string
}

func NewStateIDField() *StateIDField {
	return &StateIDField{}
}

func (f *StateIDField) EncodeMicroField() ([]byte, error) {
	result := append([]byte{byte(FieldStateID) | (byte(ExtendedTypeString) << 4)}, f.value...)
	result = append(result, 0)
	return result, nil
}

func (f *StateIDField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("microtoken: invalid field data")
	}

	if (data[0] & 0b1111) != byte(FieldStateID) {
		return nil, errors.New("microtoken: invalid field type")
	}

	extendedType := ExtendedType((data[0] >> 4) & 0b1111)
	if extendedType != ExtendedTypeString {
		return nil, errors.New("microtoken: invalid field type")
	}

	result, remainder := readString(data[1:])
	if remainder == nil {
		return nil, errors.New("microtoken: read string failed")
	}

	f.value = result

	return remainder, nil
}

func (f *StateIDField) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &f.value)
}

func (f *StateIDField) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.value)
}

func (f *StateIDField) Key() string {
	return "stateID"
}
