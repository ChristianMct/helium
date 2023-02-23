package api

import (
	"fmt"
	"strconv"
)

func (s *SignatureType) MarshalJSON() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *SignatureType) UnmarshalJSON(b []byte) error {
	bs, err := strconv.Unquote(string(b))
	if err != nil {
		bs = string(b)
	}

	// try casting as an int
	i, err := strconv.Atoi(bs)
	if err == nil {
		if i < len(SignatureType_name) {
			result := SignatureType(int32(i))
			*s = result
			return nil
		}
	}

	s1, ok := SignatureType_value[bs]
	if !ok {
		return fmt.Errorf("failed to unmarshal type")
	}

	result := SignatureType(s1)
	*s = result
	return nil
}

func (p *ProtocolType) MarshalJSON() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *ProtocolType) UnmarshalJSON(b []byte) error {
	bs, err := strconv.Unquote(string(b))
	if err != nil {
		bs = string(b)
	}

	// try casting as an int
	i, err := strconv.Atoi(bs)
	if err == nil {
		if i < len(ProtocolType_name) {
			result := ProtocolType(int32(i))
			*p = result
			return nil
		}
	}

	s1, ok := ProtocolType_value[bs]
	if !ok {
		return fmt.Errorf("failed to unmarshal type")
	}

	result := ProtocolType(s1)
	*p = result
	return nil
}

func (c *CiphertextType) MarshalJSON() ([]byte, error) {
	return []byte(c.String()), nil
}

func (c *CiphertextType) UnmarshalJSON(b []byte) error {
	bs, err := strconv.Unquote(string(b))
	if err != nil {
		bs = string(b)
	}

	// try casting as an int
	i, err := strconv.Atoi(bs)
	if err == nil {
		if i < len(CiphertextType_name) {
			result := CiphertextType(int32(i))
			*c = result
			return nil
		}
	}

	s1, ok := CiphertextType_value[bs]
	if !ok {
		return fmt.Errorf("failed to unmarshal type")
	}

	result := CiphertextType(s1)
	*c = result
	return nil
}
