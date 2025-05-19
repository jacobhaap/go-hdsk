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

// HDKey holds a Hierarchical Deterministic Key.
type HDKey = utils.HDKey

// Key holds an HD key.
type Key struct {
	Key HDKey
}

// NewPathSchema creates a new derivation path schema from a string.
//
//	schema, err := hd.NewPathSchema(`m / application: any / purpose: any / context: any / index: num`)
func NewPathSchema(schema string) (*PathSchema, error) {
	segments := strings.Split(schema, ` / `)
	if len(segments) > 256 {
		return nil, fmt.Errorf(`derivation path schema cannot exceed 256 segments, got %d`, len(segments))
	}
	if segments[0] != `m` {
		return nil, fmt.Errorf(`root segment in schema must be designated by "m", got %q`, segments[0])
	}
	allowed := map[string]bool{"str": true, "num": true, "any": true} // Allow strings and numbers ('any' for either)
	result := make([][2]string, 0, len(segments)-1)                   // Initialize 'result' slice for the parsed schema
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
	return &PathSchema{Schema: result}, nil // Return the parsed schema
}

// Parse validates and parses a derivation path from a string, using a path schema.
//
//	path, err := schema.Parse(`m/42/0/1/0`)
func (s *PathSchema) Parse(path string) (Path, error) {
	segments := strings.Split(path, `/`) // Split the path into segments
	if len(segments) == 0 || segments[0] != "m" {
		return nil, fmt.Errorf(`master key must be designated by "m", got %q`, segments[0])
	}
	indices := segments[1:] // Define indices as elements starting at index 1
	if len(indices) > len(s.Schema) {
		return nil, fmt.Errorf(`too many indices in derivation path: got %d, expected %d`, len(indices), len(s.Schema))
	}
	result := make(Path, 0, len(indices)) // Initialize 'result' slice for the parsed path
	for i, index := range indices {
		label, typ := s.Schema[i][0], s.Schema[i][1] // Get label and type for the current index 'i' from the schema
		idk, err := utils.GetIndex(index, typ)       // Parse the current index, enforcing the type from the schema
		if err != nil {
			return nil, fmt.Errorf(`derivation path: position %d label %q, %w`, i, label, err)
		}
		result = append(result, idk) // Add the parsed index to the result
	}
	return result, nil // Return the parsed derivation path
}

// NewKey creates a new key from any existing HDKey.
//
//	key := hd.NewKey(hdKey)
func NewKey(key HDKey) *Key {
	return &Key{Key: key}
}

// NewMasterKey derives a master key from a secret.
//
//	master, err := hd.NewMasterKey(`747261636B6572706C61747A`)
func NewMasterKey(secret any) (*Key, error) {
	bytes, err := utils.ToBytes(secret) // Ensure bytes of secret are used
	if err != nil {
		return nil, fmt.Errorf(`master key secret: %w`, err)
	}
	salt, err := utils.CalcSalt(bytes) // Derive a deterministic 'salt' from the secret
	if err != nil {
		return nil, fmt.Errorf(`master key salt: %w`, err)
	}
	info, err := utils.ToBytes(`symmetric_hd/master`) // Use domain-separated 'info'
	if err != nil {
		return nil, fmt.Errorf(`master key info: %w`, err)
	}
	ikm, err := hkdf.New(bytes, salt, info, 64) // Blake2b-HKDF key from an IKM of 'secret'
	if err != nil {
		return nil, fmt.Errorf(`master key hkdf: %w`, err)
	}
	split := utils.SplitIkm(ikm, []int{32, 32})   // Split 'ikm' into the master key and chain code
	fp, err := utils.Fingerprint(bytes, split[0]) // Derive a fingerprint for the master key
	if err != nil {
		return nil, fmt.Errorf(`master key fingerprint: %w`, err)
	}
	path := `m` // Define the derivation path
	key := HDKey{
		Key:         split[0], // Master key
		Code:        split[1], // Chain code
		Depth:       0,        // Depth in hierarchy
		Path:        path,     // Derivation path
		Fingerprint: fp,       // Fingerprint
	}
	return &Key{Key: key}, nil // Return a Key holding the master key
}

// NewChildKey derives a child key from a parent key, at a chosen index.
//
//	child, err := hd.NewChildKey(master.Key, 42)
func NewChildKey(parent HDKey, index int) (*Key, error) {
	i, err := utils.ToBytes(index) // Encode the index to bytes
	if err != nil {
		return nil, fmt.Errorf(`child key index: %w`, err)
	}
	salt := append(parent.Key, i...)                 // Use a salt of the parent key + index
	info, err := utils.ToBytes(`symmetric_hd/child`) // Use domain-separated 'info'
	if err != nil {
		return nil, fmt.Errorf(`child key info: %w`, err)
	}
	ikm, err := hkdf.New(parent.Code, salt, info, 64) // Blake2b-HKDF key from an IKM of the parent chain code
	if err != nil {
		return nil, fmt.Errorf(`child key hkdf: %w`, err)
	}
	split := utils.SplitIkm(ikm, []int{32, 32})        // Split 'ikm' into the child key and chain code
	fp, err := utils.Fingerprint(parent.Key, split[0]) // Derive a fingerprint for the child key
	if err != nil {
		return nil, fmt.Errorf(`child key fingerprint: %w`, err)
	}
	path := parent.Path + `/` + strconv.Itoa(index) // Define the derivation path
	key := HDKey{
		Key:         split[0],         // Child key
		Code:        split[1],         // Chain code
		Depth:       parent.Depth + 1, // Depth in hierarchy
		Path:        path,             // Derivation path
		Fingerprint: fp,               // Fingerprint
	}
	return &Key{Key: key}, nil // Return a Key holding the child key
}

// DeriveChild derives a child key from the current key, at a chosen index.
//
//	child, err := master.DeriveChild(42)
func (k *Key) DeriveChild(index any) (*Key, error) {
	var i int // Initialize 'i' for child derivation index
	switch v := index.(type) {
	case int:
		i = v // When 'index' is a number, directly use for 'i'
	case string:
		i = utils.StrToIndex(v) // When 'index' is a string, convert to integer
	default:
		return nil, fmt.Errorf(`child key: invalid index type`) // Return an error when 'index' is not a number or a string
	}
	return NewChildKey(k.Key, i) // Return a new child key at the selected index 'i'
}

// DeriveHdKey derives an HD key from a parent key and derivation path.
//
// key, err := hd.DeriveHdKey(master, path)
func DeriveHdKey(parent *Key, path Path) (*Key, error) {
	key, err := parent.DeriveChild(path[0]) // Initialize 'key' with first index from the path
	if err != nil {
		return nil, fmt.Errorf(`hd key initialization: %w`, err)
	}
	for i := 1; i < len(path); i++ {
		index := path[i]                  // Get the current index
		key, err = key.DeriveChild(index) // Derive a child key from 'key' for the current index
		if err != nil {
			return nil, fmt.Errorf(`hd key derivation: %w`, err)
		}
	}
	return key, nil // Return the HD key
}

// Lineage checkls if a key is a direct child of a given parent key.
//
//	lineage, err := child.Lineage(master.Key)
func (k *Key) Lineage(parent HDKey) (bool, error) {
	return utils.VerifyFp(k.Key, parent) // Verify the key's fingerprint against a parent key
}
