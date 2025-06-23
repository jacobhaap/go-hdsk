// Package hdsk provides implementation of Hierarchical Deterministic Symmetric Keys,
// a method of symmetric key generation using schema-driven derivation paths for generating
// nodes in hierarchies descending from master keys.
package hdsk

import (
	"crypto/hkdf"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/jacobhaap/go-hdsk/internal/utils"
)

// HDSchema is a derivation path schema.
type HDSchema [][2]string

// HDPath is a derivation path.
type HDPath []uint32

// HDKey holds a Hierarchical Deterministic Key.
type HDKey struct {
	Key         []byte // Cryptographic key.
	Code        []byte // Chain code.
	Depth       uint32 // Depth in hierarchy.
	Fingerprint []byte // Key fingerprint.
}

// DefaultSchema is the default derivation path schema.
const DefaultSchema string = "m / application: any / purpose: any / context: any / index: num"

// DefaultPath is the default derivation path.
const DefaultPath string = "m/42/0/1/0"

// Schema parses a new derivation path schema from a given string.
func Schema(str string) (HDSchema, error) {
	segments := strings.Split(str, " / ")
	if len(segments) > 256 {
		return nil, fmt.Errorf(`schema cannot exceed 256 segments, got %d`, len(segments))
	}
	if segments[0] != "m" {
		return nil, fmt.Errorf(`schema must begin with %q, got %q`, "m", segments[0])
	}
	allowed := map[string]bool{"str": true, "num": true, "any": true} // Allow strings, numbers, or either
	result := make([][2]string, 0, len(segments)-1)                   // Allocate slice for the parsed schema
	for _, segment := range segments[1:] {
		parts := strings.Split(segment, ":") // Split each segment into two parts
		label := strings.TrimSpace(parts[0]) // Extract the label from the first part
		typ := strings.TrimSpace(parts[1])   // Extract the type from the second part
		if label == "" || typ == "" {
			return nil, fmt.Errorf(`invalid segment in schema, %q`, segment)
		}
		if !allowed[typ] {
			return nil, fmt.Errorf(`invalid type %q for label %q in schema`, typ, label)
		}
		result = append(result, [2]string{label, typ}) // Add the label and type to the parsed results
	}
	return result, nil // Return the parsed schema
}

// Path parses a new derivation path from a given hash, string, and schema.
func Path(h func() hash.Hash, str string, schema HDSchema) (HDPath, error) {
	segments := strings.Split(str, "/")
	if len(segments) == 0 || segments[0] != "m" {
		return nil, fmt.Errorf(`derivation path must begin with %q, got %q`, "m", segments[0])
	}
	indices := segments[1:] // Define indices as elements starting at index 1
	if len(indices) > len(schema) {
		return nil, fmt.Errorf(`too many indices in derivation path: got %d, expected %d`, len(indices), len(schema))
	}
	result := make(HDPath, 0, len(indices)) // Allocate slice for the parsed path
	for i, index := range indices {
		label, typ := schema[i][0], schema[i][1]  // Get label and type for the current index from the schema
		idx, err := utils.GetIndex(h, index, typ) // Parse the current index, enforcing the type from the schema
		if err != nil {
			return nil, fmt.Errorf(`derivation path position %d label %q, %w`, i, label, err)
		}
		result = append(result, idx) // Add the parsed index to the result
	}
	return result, nil // Return the parsed derivation path
}

// Master derives a new master key from a given hash and secret.
func Master(h func() hash.Hash, secret []byte) (HDKey, error) {
	salt, err := utils.CalcSalt(h, secret, nil) // Derive salt from the secret
	if err != nil {
		return HDKey{}, fmt.Errorf(`master key salt, %w`, err)
	}
	ikm, err := hkdf.Key(h, secret, salt, "MASTER", 64) // Derive ikm from secret
	if err != nil {
		return HDKey{}, fmt.Errorf(`master key hkdf, %w`, err)
	}
	master := ikm[:32]                              // First 32 bytes as the key
	code := ikm[32:64]                              // Last 32 bytes as the chain code
	fp, err := utils.Fingerprint(h, secret, master) // Derive a fingerprint for the master key
	if err != nil {
		return HDKey{}, fmt.Errorf(`master key fingerprint, %w`, err)
	}
	key := HDKey{
		Key:         master,
		Code:        code,
		Depth:       0,
		Fingerprint: fp,
	}
	return key, nil // Return the master HD key
}

// Child derives a new child key from a given hash, master key, and index.
func Child(h func() hash.Hash, master *HDKey, index uint32) (HDKey, error) {
	info1 := make([]byte, 4)
	binary.BigEndian.PutUint32(info1, index)           // Context info from bytes of encoded index
	salt, err := utils.CalcSalt(h, master.Code, info1) // Derive salt from the master code
	if err != nil {
		return HDKey{}, fmt.Errorf(`child key salt, %w`, err)
	}
	info2 := "CHILD" + strconv.Itoa(int(index))           // Construct info for HKDF form CHILD + index string
	ikm, err := hkdf.Key(h, master.Code, salt, info2, 64) // Derive ikm from master chain code
	if err != nil {
		return HDKey{}, fmt.Errorf(`child key hkdf, %w`, err)
	}
	child := ikm[:32]                                  // First 32 bytes as the key
	code := ikm[32:64]                                 // Last 32 bytes as the chain code
	fp, err := utils.Fingerprint(h, master.Key, child) // Derive a fingerprint for the child key
	if err != nil {
		return HDKey{}, fmt.Errorf(`child key fingerprint, %w`, err)
	}
	key := HDKey{
		Key:         child,
		Code:        code,
		Depth:       master.Depth + 1,
		Fingerprint: fp,
	}
	return key, nil // Return the child HD key
}

// Node derives a new key at a node in a hierarchy descending from a master key, from a given
// hash, master key, and derivation path.
func Node(h func() hash.Hash, master *HDKey, path HDPath) (HDKey, error) {
	key, err := Child(h, master, path[0]) // Initialize key with first index from the path
	if err != nil {
		return HDKey{}, fmt.Errorf(`node initialization, %w`, err)
	}
	for i := 1; i < len(path); i++ {
		index := path[i]                 // Get the current index
		key, err = Child(h, &key, index) // Derive a child of key for the current index
		if err != nil {
			return HDKey{}, fmt.Errorf(`node derivation, %w`, err)
		}
	}
	return key, nil // Return the HD key
}

// Lineage checks if a key is the direct child of a master key, from a given hash, child key, and master key.
func Lineage(h func() hash.Hash, child, master *HDKey) (bool, error) {
	fp1 := child.Fingerprint                                // Extract the child fingerprint as fp1
	fp2, err := utils.Fingerprint(h, master.Key, child.Key) // Derive fp2 from the master and child keys
	if err != nil {
		return false, fmt.Errorf(`lineage fingerprint recalculation, %w`, err)
	}
	if len(fp1) != 16 || len(fp2) != 16 {
		return false, errors.New(`fingerprints for lineage verification must be 16 bytes each`)
	}
	// Complete a constant-time comparison between the 16 bytes of each fingerprint
	var result byte = 0
	for i := range 16 {
		result |= fp1[i] ^ fp2[i]
	}
	return result == 0, nil // Return a boolean result of the byte comparison
}
