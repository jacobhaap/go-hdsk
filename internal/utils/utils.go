// Package utils provides symmetric-hd utilities.
package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"github.com/jacobhaap/go-symmetric-hd/internal/hkdf"
	"golang.org/x/crypto/blake2b"
)

// HDKey holds a Hierarchical Deterministic Key.
type HDKey struct {
	Key         []uint8 // Key
	Code        []uint8 // Chain code
	Depth       int     // Depth in hierarchy
	Path        string  // Derivation path
	Fingerprint []uint8 // Fingerprint
}

// hexRegex is hexadecimal string regexp.
var hexRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// numRegex is numeric string regexp.
var numRegex = regexp.MustCompile(`^\d+$`)

// strRegex is alphabetic string regexp.
var strRegex = regexp.MustCompile(`^[a-zA-Z\-]+$`)

// isHex checks if a string is hexadecimal, returning a boolean value.
func isHex(str string) bool {
	return len(str)%2 == 0 && hexRegex.MatchString(str)
}

// isNumber checks if a string is numeric.
func isNumber(str string) bool {
	return numRegex.MatchString(str)
}

// isString checks if a string is alphabetic.
func isString(str string) bool {
	return strRegex.MatchString(str)
}

// utf8ToBytes converts a UTF-8 encoded string to a uint8 slice.
func utf8ToBytes(str string) []uint8 {
	return []uint8(str)
}

// strToBytes converts a string (UTF-8 or Hex) to a uint8 slice.
func strToBytes(str string) ([]uint8, error) {
	// Check if the string is hex encoded
	if isHex(str) {
		// Convert hex string to bytes
		return hex.DecodeString(str)
	}
	// If not hex encoded, convert UTF-8 to bytes
	return utf8ToBytes(str), nil
}

// intToBytes encodes an integer number as a 4 byte uint8 slice
func intToBytes(num int) []uint8 {
	return []uint8{
		uint8(num >> 24),
		uint8(num >> 16),
		uint8(num >> 8),
		uint8(num),
	}
}

// ToBytes returns a uint8 slice from an input.
//
// Supports string, int, and byte input. When the input is a
// string, it is handled as either hex or UTF-8 encoded.
func ToBytes(input any) ([]uint8, error) {
	switch v := input.(type) {
	case string:
		return strToBytes(v) // Convert to bytes when a string
	case int:
		return intToBytes(v), nil // Convert to bytes when an integer
	case []uint8:
		return v, nil // Return the input when already a uint8 slice
	default:
		return nil, fmt.Errorf(`invalid type for byte conversion`)
	}
}

// CalcSalt calculates a domain-separated salt for a secret.
func CalcSalt(secret []uint8) ([]uint8, error) {
	label, err := strToBytes(`symmetric_hd/salt`) // Domain-separated label
	if err != nil {
		return nil, err
	}
	mac, err := blake2b.New(16, label) // Create a 16 byte blake2b MAC
	if err != nil {
		return nil, err
	}
	mac.Write(secret)                          // Write 'secret' to the MAC
	return append(label, mac.Sum(nil)...), nil // Return bytes of 'label' + 'mac'
}

// StrToIndex obtains an index number in the range 0 to 2^31 - 1 from a string.
func StrToIndex(str string) int {
	hash := blake2b.Sum256([]uint8(str))        // Take a blake2b hash of the string
	value := binary.BigEndian.Uint32(hash[0:4]) // Get a 32 bit integer from the hash
	return int(value % 0x80000000)              // Return index number in the defined range
}

// isValidIndex checks if an index number is in the range 0 to 2^31 - 1.
func isValidIndex(i int) bool {
	return i >= 0 && i <= 0x7FFFFFFF
}

// GetIndex gets an index number from a string, with type enforcement.
func GetIndex(index string, typ string) (int, error) {
	var i int
	switch typ {
	case "num":
		if !isNumber(index) {
			return 0, fmt.Errorf(`invalid number index, %q`, index)
		}
		i, _ = strconv.Atoi(index) // Convert string number to an integer
	case "str":
		if !isString(index) {
			return 0, fmt.Errorf(`invalid string index, %q`, index)
		}
		i = StrToIndex(index) // Convert alphabetic string to an index integer
	case "any":
		if isNumber(index) {
			i, _ = strconv.Atoi(index) // Convert to integer
		} else if isString(index) {
			i = StrToIndex(index) // Convert to numeric index
		} else {
			return 0, fmt.Errorf(`invalid index, %q`, index)
		}
	default:
		return 0, fmt.Errorf(`invalid type, %q`, typ)
	}
	if isValidIndex(i) {
		return i, nil // Return if the index 'i' is in range
	} else {
		return 0, fmt.Errorf(`out of range index, %q`, i)
	}
}

// Fingerprint calculates a fingerprint from a parent key and child key.
func Fingerprint(parent []uint8, child []uint8) ([]uint8, error) {
	salt, err := CalcSalt(parent) // Derive a deterministic 'salt' from the parent key
	if err != nil {
		return nil, err
	}
	info, err := strToBytes(`symmetric_hd/fingerprint`) // Use domain-separated label as the 'info'
	if err != nil {
		return nil, err
	}
	key, err := hkdf.New(parent, salt, info, 32) // Blake2b-HKDF key from an IKM of 'parent'
	if err != nil {
		return nil, err
	}
	mac, err := blake2b.New(16, key) // Create a 16 byte blake2b MAC
	if err != nil {
		return nil, err
	}
	mac.Write(child)         // Write 'child' to the MAC
	return mac.Sum(nil), nil // Return MAC as fingerprint
}

// VerifyFp verifies a child key's fingerprint against a parent key.
func VerifyFp(child HDKey, parent HDKey) (bool, error) {
	fp1 := child.Fingerprint                       // Extract the child fingerprint as 'fp1'
	fp2, err := Fingerprint(parent.Key, child.Key) // Derive 'fp2' from the parent and child keys
	if err != nil {
		return false, err
	}
	if len(fp1) != 16 || len(fp2) != 16 {
		return false, nil // Return false if the fingerprints are not 16 bytes each
	}
	// Complete a constant-time comparison between the 16 bytes of each fingerprint
	var result uint8 = 0
	for i := 0; i < 16; i++ {
		result |= fp1[i] ^ fp2[i]
	}
	return result == 0, nil // Return a boolean result of the byte comparison
}

// SplitIkm splits initial keying material into an slice of uint8 slices, based on a slice of sizes.
func SplitIkm(bytes []uint8, sizes []int) [][]uint8 {
	result := make([][]uint8, 0, len(sizes)) // Allocate result slice for the split ikm
	offset := 0                              // Start at index 0 in 'bytes'
	for _, length := range sizes {
		seg := make([]uint8, length)           // Create a new slice for the segment
		copy(seg, bytes[offset:offset+length]) // Copy the segment into the new slice
		result = append(result, seg)           // Add the segment to 'result'
		offset += length                       // Increment the offset by 'len'
	}
	return result // Return the split ikm
}
