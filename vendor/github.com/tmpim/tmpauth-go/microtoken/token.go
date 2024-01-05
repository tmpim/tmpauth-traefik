package microtoken

import (
	"errors"
)

type TokenField struct {
	tokenData []byte
}

func NewTokenField() *TokenField {
	return &TokenField{}
}

func (f *TokenField) EncodeMicroField() ([]byte, error) {
	length := len(f.tokenData)

	if length >= 1<<(8+3) {
		return nil, errors.New("microtoken: token data too long")
	}

	return append([]byte{
		byte(FieldToken) | (byte(ExtendedTypeVariationsFlag) << 4) | (byte(length>>8) << 4),
		byte(length & 0xFF),
	}, f.tokenData...), nil
}

func (f *TokenField) DecodeMicroField(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, errors.New("microtoken: invalid field data")
	}

	if (data[0] & 0b1111) != byte(FieldToken) {
		return nil, errors.New("microtoken: invalid field type")
	}

	extendedType := ExtendedType((data[0] >> 4) & 0b1111)
	if extendedType&ExtendedTypeVariationsFlag == 0 {
		return nil, errors.New("microtoken: invalid field type")
	}

	length := int((data[0]>>4)&0b111)<<8 | int(data[1])

	if length > len(data)-2 {
		return nil, errors.New("microtoken: invalid field data")
	}

	f.tokenData = data[2 : 2+length]
	return data[2+length:], nil
}

func (f *TokenField) UnmarshalJSON(data []byte) error {
	return errors.New("unimplemented")
}

func (f *TokenField) MarshalJSON() ([]byte, error) {
	return nil, errors.New("unimplemented")
}

func (f *TokenField) Key() string {
	return "token"
}
