package microtoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"errors"

	"github.com/iancoleman/orderedmap"
)

type FieldType byte

const (
	FieldIAT = FieldType(iota + 1)
	FieldEXP
	FieldNBF
	FieldISS
	FieldSUB
	FieldAUD
	FieldToken
	FieldKID
	FieldStateID
	FieldCustom = FieldType(0b1110)
)

type ExtendedType byte

const (
	ExtendedTypeNumber = ExtendedType(iota)
	ExtendedTypeString
	ExtendedTypeBool
	ExtendedTypeRawJSON
	ExtendedTypeVariationsFlag = ExtendedType(0b1000)
)

var FieldNames = map[string]FieldType{
	"iat":     FieldIAT,
	"exp":     FieldEXP,
	"nbf":     FieldNBF,
	"iss":     FieldISS,
	"sub":     FieldSUB,
	"aud":     FieldAUD,
	"token":   FieldToken,
	"stateID": FieldStateID,
	"kid":     FieldKID,
}

type Field interface {
	EncodeMicroField() ([]byte, error)
	DecodeMicroField([]byte) ([]byte, error)
	Key() string
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

func (p *Codec) EncodeToken(token []byte) ([]byte, error) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, errors.New("microtoken: invalid wrapped token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("microtoken: invalid payload: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("microtoken: invalid signature: %w", err)
	}

	fields := orderedmap.New()
	err = json.Unmarshal(payload, &fields)
	if err != nil {
		return nil, fmt.Errorf("microtoken: invalid payload: %w", err)
	}

	var rawData map[string]json.RawMessage
	err = json.Unmarshal(payload, &rawData)
	if err != nil {
		return nil, fmt.Errorf("microtoken: invalid payload: %w", err)
	}

	var compiledFields []Field

	var result []byte
	for _, key := range fields.Keys() {
		var field Field

		fieldType, found := FieldNames[key]
		if found {
			if fieldType == FieldToken {
				// this is the token! we need to parse this first.
				var internalToken string
				err := json.Unmarshal(rawData[key], &internalToken)
				if err != nil {
					return nil, fmt.Errorf("microtoken: invalid internal token: %w", err)
				}

				log.Println("--------------- begin internal token ------------------")
				var internalTokenBytes []byte
				internalTokenBytes, err = p.EncodeToken([]byte(internalToken))
				log.Println("---------------- end internal token -------------------")
				if err != nil {
					return nil, fmt.Errorf("microtoken: invalid internal token: %w", err)
				}

				tokenField := NewTokenField()
				tokenField.tokenData = internalTokenBytes
				compiledFields = append(compiledFields, tokenField)

				field = nil
			} else {
				field = codecMapping[fieldType](p)
			}
		} else {
			field = NewGenericField(key)
		}

		if field != nil {
			err := field.UnmarshalJSON(rawData[key])
			if err != nil {
				return nil, fmt.Errorf("microtoken: invalid field %q: %w", key, err)
			}

			compiledFields = append(compiledFields, field)
		}
	}

	for _, field := range compiledFields {
		fieldData, err := field.EncodeMicroField()
		if err != nil {
			return nil, fmt.Errorf("microtoken: failed to encode field %q: %w", field.Key(), err)
		}

		log.Printf("field %q is %d bytes", field.Key(), len(fieldData))

		result = append(result, fieldData...)
	}

	result = append(signature, result...)

	log.Printf("signature is %d bytes", len(signature))

	return result, nil
}

type Codec struct {
	ClientID   string
	AuthDomain string
}

var codecMapping = map[FieldType]func(d *Codec) Field{
	FieldIAT:     func(d *Codec) Field { return NewTimestampField(FieldIAT) },
	FieldEXP:     func(d *Codec) Field { return NewTimestampField(FieldEXP) },
	FieldNBF:     func(d *Codec) Field { return NewTimestampField(FieldNBF) },
	FieldISS:     func(d *Codec) Field { return NewOriginField(FieldISS, d.ClientID, d.AuthDomain) },
	FieldSUB:     func(d *Codec) Field { return NewSubjectField() },
	FieldAUD:     func(d *Codec) Field { return NewOriginField(FieldAUD, d.ClientID, d.AuthDomain) },
	FieldToken:   func(d *Codec) Field { return NewTokenField() },
	FieldStateID: func(d *Codec) Field { return NewStateIDField() },
	FieldKID:     func(d *Codec) Field { return NewKidField() },
	FieldCustom:  func(d *Codec) Field { return NewGenericField("") },
}

var (
	HS256Header = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	ES256Header = []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9")
)

func (p *Codec) DecodeToken(jwtHeader []byte, data []byte) ([]byte, error) {
	if len(data) <= 64 {
		return nil, errors.New("microtoken: invalid token length")
	}

	var signature []byte

	if bytes.Equal(jwtHeader, HS256Header) {
		signature = data[:32]
		data = data[32:]
	} else if bytes.Equal(jwtHeader, ES256Header) {
		signature = data[:64]
		data = data[64:]
	}

	result := orderedmap.New()
	for {
		var field Field
		var err error
		field, data, err = p.DecodeField(data)
		if err != nil {
			return nil, err
		}

		if field == nil {
			break
		}

		if tokenField, ok := field.(*TokenField); ok {
			internalToken, err := p.DecodeToken(ES256Header, tokenField.tokenData)
			if err != nil {
				return nil, fmt.Errorf("microtoken: failed to decode internal token: %w", err)
			}

			result.Set(field.Key(), string(internalToken))
		} else {
			jsonValue, err := field.MarshalJSON()
			if err != nil {
				return nil, fmt.Errorf("microtoken: failed to marshal field %q: %w", field.Key(), err)
			}

			result.Set(field.Key(), json.RawMessage(jsonValue))
		}
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("microtoken: failed to marshal token: %w", err)
	}

	wrappedToken := string(jwtHeader) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
	return []byte(wrappedToken), nil
}

func (p *Codec) DecodeField(data []byte) (Field, []byte, error) {
	if len(data) == 0 {
		return nil, nil, nil
	}

	fieldType := FieldType(data[0] & 0b1111)

	fieldGenerator, ok := codecMapping[fieldType]
	if !ok {
		return nil, nil, fmt.Errorf("microtoken: invalid field type: %v", fieldType)
	}

	field := fieldGenerator(p)
	remainder, err := field.DecodeMicroField(data)
	return field, remainder, err
}

func readString(data []byte) (string, []byte) {
	for i := range data {
		if data[i] == 0 {
			return string(data[:i]), data[i+1:]
		}
	}

	return "", nil
}
