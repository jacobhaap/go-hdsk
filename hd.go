// Package hd provides functionality for symmetric hierarchical deterministic key derivation.
// This includes support for deriving master keys, child keys, keys in a nested hierarchy using
// a derivation path, and the validation and parsing of derivation paths using a schema.
package hd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jacobhaap/go-symmetric-hd/internal/hkdf"
	"github.com/jacobhaap/go-symmetric-hd/internal/utils"
)

// Path is a derivation path.
type Path []int

// PathSchema holds a derivation path schema.
type PathSchema struct {
	Schema [][2]string
}

// Key holds an HD key.
type Key struct {
	Key utils.HDKey
}

// NewPathSchema creates a new derivation path schema from a string.
func NewPathSchema(schema string) (*PathSchema, error) {
	segments := strings.Split(schema, ` / `) // Split the schema into segments
	if len(segments) > 256 {                 // Check if there are more than 256 segments
		return nil, fmt.Errorf(`derivation path schema cannot exceed 256 segments, got "%d"`, len(segments)) // Return an error
	}
	if segments[0] != `m` { // Check if the root segment is not identified by 'm'
		return nil, fmt.Errorf(`root segment must be designated by "m", got "%s"`, segments[0]) // Return an error
	}
	allowed := map[string]bool{"str": true, "num": true, "any": true} // Allow strings and numbers ('any' for either)
	result := make([][2]string, 0, len(segments)-1)                   // Initialize 'result' slice for the parsed schema
	for _, segment := range segments[1:] {                            // Iterate over segments of the schema, starting after the root
		parts := strings.Split(segment, ":") // Split each segment into two parts
		label := strings.TrimSpace(parts[0]) // Extract the label from the first part
		typ := strings.TrimSpace(parts[1])   // Extract the type from the second part
		if label == "" || typ == "" {        // Check if the label or type is missing
			return nil, fmt.Errorf(`invalid segment, "%s"`, segment) // Return an error
		}
		if !allowed[typ] { // Check if the type matches an allowed type
			return nil, fmt.Errorf(`invalid type "%s" for label "%s"`, typ, label) // Return an error
		}
		result = append(result, [2]string{label, typ}) // Add the label and type to the parsed results
	}
	return &PathSchema{Schema: result}, nil // Return the parsed schema
}

// Parse validates and parses a derivation path from a string, using a path schema.
func (s *PathSchema) Parse(path string) (Path, error) {
	segments := strings.Split(path, `/`)          // Split the path into segments
	if len(segments) == 0 || segments[0] != "m" { // Check if the root segment is not identified by 'm'
		return nil, fmt.Errorf(`master key must be designated by "m", got "%s"`, segments[0]) // Return an error
	}
	indices := segments[1:]           // Define indices as elements starting at index 1
	if len(indices) > len(s.Schema) { // Check if the indices exceed the schema length
		return nil, fmt.Errorf(`too many indices: got "%d", expected "%d"`, len(indices), len(s.Schema)) // Return an error
	}
	result := make(Path, 0, len(indices)) // Initialize 'result' slice for the parsed path
	for i, index := range indices {       // Iterate over the indices
		label, typ := s.Schema[i][0], s.Schema[i][1] // Get label and type for the current index 'i' from the schema
		idk, err := utils.GetIndex(index, typ)       // Parse the current index, enforcing the type from the schema
		if err != nil {                              // Check if 'utils.GetIndex' encountered an error
			return nil, fmt.Errorf(`position "%d" label "%s", %v`, i, label, err) // Return an error
		}
		result = append(result, idk) // Add the parsed index to the result
	}
	return result, nil // Return the parsed derivation path
}

// NewKey creates a new key from any existing HDKey.
func NewKey(key utils.HDKey) *Key {
	return &Key{Key: key}
}

// NewMasterKey derives a master key from a secret.
func NewMasterKey(secret interface{}) (*Key, error) {
	bytes, err := utils.ToBytes(secret) // Ensure bytes of secret are used
	if err != nil {                     // Check if 'utils.ToBytes' encountered an error
		return nil, err // Return an error
	}
	salt, err := utils.CalcSalt(bytes) // Derive a deterministic 'salt' from the secret
	if err != nil {                    // Check if 'utils.CalcSalt' encountered an error
		return nil, err // Return an error
	}
	info, err := utils.ToBytes(`symmetric_hd/master`) // Use domain-separated 'info'
	if err != nil {                                   // Check if 'utils.ToBytes' encountered an error
		return nil, err // Return an error
	}
	ikm, err := hkdf.Hkdf(bytes, salt, info, 64) // Blake2b-HKDF key from an IKM of 'secret'
	if err != nil {                              // Check if 'hkdf.Hkdf' encountered an error
		return nil, err // Return an error
	}
	split := utils.SplitIkm(ikm, []int{32, 32})   // Split 'ikm' into the master key and chain code
	fp, err := utils.Fingerprint(bytes, split[0]) // Derive a fingerprint for the master key
	if err != nil {                               // Check if 'utils.Fingerprint' encountered an error
		return nil, err // Return an error
	}
	path := `m` // Define the derivation path
	key := utils.HDKey{
		Key:         split[0], // Master key
		Code:        split[1], // Chain code
		Depth:       0,        // Depth in hierarchy
		Path:        path,     // Derivation path
		Fingerprint: fp,       // Fingerprint
	}
	return &Key{Key: key}, nil // Return a Key holding the master key
}

// NewChildKey derives a child key from a parent key, at a chosen index.
func NewChildKey(parent utils.HDKey, index int) (*Key, error) {
	salt := append(parent.Key, utils.EncodeIndex(index)...) // Use a salt of the parent key + index
	info, err := utils.ToBytes(`symmetric_hd/child`)        // Use domain-separated 'info'
	if err != nil {                                         // Check if 'utils.ToBytes' encountered an error
		return nil, err // Return an error
	}
	ikm, err := hkdf.Hkdf(parent.Code, salt, info, 64) // Blake2b-HKDF key from an IKM of the parent chain code
	if err != nil {                                    // Check if 'utils.Hkdf' encountered an error
		return nil, err // Return an error
	}
	split := utils.SplitIkm(ikm, []int{32, 32})        // Split 'ikm' into the child key and chain code
	fp, err := utils.Fingerprint(parent.Key, split[0]) // Derive a fingerprint for the child key
	if err != nil {                                    // Check if 'utils.Fingerprint' encountered an error
		return nil, err // Return an error
	}
	path := parent.Path + `/` + strconv.Itoa(index) // Define the derivation path
	key := utils.HDKey{
		Key:         split[0],         // Child key
		Code:        split[1],         // Chain code
		Depth:       parent.Depth + 1, // Depth in hierarchy
		Path:        path,             // Derivation path
		Fingerprint: fp,               // Fingerprint
	}
	return &Key{Key: key}, nil // Return a Key holding the child key
}

// DeriveChild derives a child key from the current key, at a chosen index.
func (k *Key) DeriveChild(index interface{}) (*Key, error) {
	var i int // Initialize 'i' for child derivation index
	switch v := index.(type) {
	case int:
		i = v // When 'index' is a number, directly use for 'i'
	case string:
		i = utils.StrToIndex(v) // When 'index' is a string, convert to integer
	default:
		return nil, fmt.Errorf(`invalid index`) // Return an error when 'index' is not a number or a string
	}
	return NewChildKey(k.Key, i) // Return a new child key at the selected index 'i'
}

// DeriveHdKey derives an HD key from a parent key and derivation path.
func DeriveHdKey(parent *Key, path Path) (*Key, error) {
	key, err := parent.DeriveChild(path[0]) // Initialize 'key' with first index from the path
	if err != nil {                         // Check if 'parent.DeriveChild' encountered an error
		return nil, err // Return an error
	}
	for i := 1; i < len(path); i++ { // Iterate over indices of the derivation path
		index := path[i]                  // Get the current index
		key, err = key.DeriveChild(index) // Derive a child key from 'key' for the current index
		if err != nil {                   // Check if 'parent.DeriveChild' encountered an error
			return nil, err // Return an error
		}
	}
	return key, nil // Return the HD key
}

// Lineage checkls if a key is a direct child of a given parent key.
func (k *Key) Lineage(parent utils.HDKey) (bool, error) {
	return utils.VerifyFp(k.Key, parent) // Verify the key's fingerprint against a parent key
}
