// Package utils provides hdsk utilities.
package utils

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
)

// CalcSalt creates a 16 byte salt from a given hash, message, and optional context info.
func CalcSalt(h func() hash.Hash, msg, info []byte) ([]byte, error) {
	if info != nil {
		hasher := h()
		_, err := hasher.Write(info) // Hash to expand the info
		if err != nil {
			return nil, fmt.Errorf(`CalcSalt hasher.Write, %w`, err)
		}
		info = hasher.Sum(nil)[:16] // Expanded info from hash digest
	} else {
		info = make([]byte, 16) // 16 byte slice
	}
	mac := hmac.New(h, info) // Create HMAC using info
	_, err := mac.Write(msg)
	if err != nil {
		return nil, fmt.Errorf(`CalcSalt mac.Write msg, %w`, err)
	}
	domain := []byte{83, 65, 76, 84} // Bytes SALT for domain separation
	_, err = mac.Write(domain)
	if err != nil {
		return nil, fmt.Errorf(`CalcSalt mac.Write domain, %w`, err)
	}
	return mac.Sum(nil)[:16], nil // Return a salt from the MAC digest
}

// EncodeInt encodes a given integer as a 4 byte slice.
func EncodeInt(num int) []byte {
	return []byte{
		byte(num >> 24),
		byte(num >> 16),
		byte(num >> 8),
		byte(num),
	}
}

// StrToIndex obtains an integer in the range 0 to 2^31 - 1 from a given hash and string.
func StrToIndex(h func() hash.Hash, str string) (int, error) {
	hasher := h()                       // Create hash
	_, err := hasher.Write([]byte(str)) // Write string to the hash
	if err != nil {
		return 0, fmt.Errorf(`StrToIndex hasher.Write, %w`, err)
	}
	sum := hasher.Sum(nil)
	value := binary.BigEndian.Uint32(sum[0:4]) // Get a 32 bit integer from the hash
	return int(value % 0x80000000), nil        // Return integer in the defined range
}

// isValidIndex checks if a given index is in the range 0 to 2^31 - 1.
func isValidIndex(i int) bool {
	return i >= 0 && i <= 0x7FFFFFFF
}

// GetIndex obtains an in-range integer index from a given hash, index string, and type.
func GetIndex(h func() hash.Hash, index, typ string) (int, error) {
	var i int
	var err error
	switch typ {
	case "num":
		i, err = strconv.Atoi(index) // Parse string to integer
		if err != nil {
			return 0, fmt.Errorf(`GetIndex invalid numeric index %q, %w`, index, err)
		}
	case "str":
		i, err = StrToIndex(h, index) // Convert string to an integer
		if err != nil {
			return 0, fmt.Errorf(`GetIndex invalid alphabetic index %q, %w`, index, err)
		}
	case "any":
		i, err = strconv.Atoi(index) // Try parsing integer first
		if err != nil {
			i, err = StrToIndex(h, index) // Try string conversion next
			if err != nil {
				return 0, fmt.Errorf(`GetIndex invalid index %q, %w`, index, err)
			}
		}
	default:
		return 0, fmt.Errorf(`GetIndex invalid type %q`, typ)
	}
	if isValidIndex(i) {
		return i, nil // Return if i is in range
	} else {
		return 0, fmt.Errorf(`GetIndex out of range index %q`, i)
	}
}

// Fingerprint calculates a fingerprint from a given hash, parent key, and child key.
func Fingerprint(h func() hash.Hash, parent, child []byte) ([]byte, error) {
	mac := hmac.New(h, parent) // Create an HMAC using the parent
	_, err := mac.Write(child) // Write the child to the MAC
	if err != nil {
		return nil, fmt.Errorf(`Fingerprint mac.Write, %w`, err)
	}
	return mac.Sum(nil)[:16], nil // Return the MAC as the fingerprint
}
