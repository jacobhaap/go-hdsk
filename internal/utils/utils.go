// Package utils provides hdsk utilities.
package utils

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
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
			return nil, err
		}
		info = hasher.Sum(nil)[:16] // Expanded info from hash digest
	} else {
		info = make([]byte, 16) // 16 byte slice
	}
	mac := hmac.New(h, info) // Create HMAC using info
	_, err := mac.Write(msg)
	if err != nil {
		return nil, err
	}
	domain := []byte{83, 65, 76, 84} // Bytes SALT for domain separation
	_, err = mac.Write(domain)
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil)[:16], nil // Return a salt from the MAC digest
}

// strToIndex obtains a 32 bit integer from a given hash and string.
func strToIndex(h func() hash.Hash, str string) (uint32, error) {
	hasher := h()                       // Create hash
	_, err := hasher.Write([]byte(str)) // Write string to the hash
	if err != nil {
		return 0, err
	}
	sum := hasher.Sum(nil)
	value := binary.BigEndian.Uint32(sum[0:4]) // Get a 32 bit integer from the hash
	return value, nil
}

// GetIndex obtains a 32 bit integer index from a given hash, index string, and type.
func GetIndex(h func() hash.Hash, index, typ string) (uint32, error) {
	var i uint32
	var err error
	switch typ {
	case "num":
		u64, err := strconv.ParseUint(index, 10, 32) // Parse string to integer
		if u64 > 0xFFFFFFFF {
			return 0, errors.New(`parsed index outside of uint32 range`)
		}
		i = uint32(u64)
		if err != nil {
			return 0, fmt.Errorf(`invalid numeric index %q, %w`, index, err)
		}
	case "str":
		i, err = strToIndex(h, index) // Convert string to an integer
		if err != nil {
			return 0, fmt.Errorf(`invalid alphabetic index %q, %w`, index, err)
		}
	case "any":
		u64, err := strconv.ParseUint(index, 10, 32) // Try parsing integer first
		if u64 > 0xFFFFFFFF {
			return 0, errors.New(`parsed index outside of uint32 range`)
		}
		i = uint32(u64)
		if err != nil {
			i, err = strToIndex(h, index) // Try string conversion next
			if err != nil {
				return 0, fmt.Errorf(`invalid index %q, %w`, index, err)
			}
		}
	default:
		return 0, fmt.Errorf(`invalid index type %q`, typ)
	}
	return i, nil // Return the index
}

// Fingerprint calculates a fingerprint from a given hash, parent key, and child key.
func Fingerprint(h func() hash.Hash, parent, child []byte) ([]byte, error) {
	mac := hmac.New(h, parent) // Create an HMAC using the parent
	_, err := mac.Write(child) // Write the child to the MAC
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil)[:16], nil // Return the MAC as the fingerprint
}
