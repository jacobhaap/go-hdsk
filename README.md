# Go HDSK
Go HDSK is an implementation of Hierarchical Deterministic Symmetric Keys, a method of symmetric key generation using schema-driven derivation paths for generating nodes in hierarchies descending from master keys.

This is a reference implementation of the specification titled *["Hierarchical Deterministic Symmetric Keys"](https://gist.github.com/jacobhaap/d75c96f61bcc32154498842e620a3261)*.

## Types
Parsed derivation path schemas are of the `HDPath` type, and parsed derivation paths are of the `HDSchema` type. All keys derived by this library are of the `HDKey` type, a struct that holds the 32 byte cryptographic key, 32 byte chain code, an integer representing the hierarchical depth, and a 16 byte fingerprint.
```go
type HDPath []int

type HDSchema [][2]string

type HDKey struct {
	Key         []byte
	Code        []byte
	Depth       int
	Fingerprint []byte
}
```

## Derivation Paths
When generating a node in a hierarchy descending from a master key, a derivation path is required. The expected length and expected types for child key indices of a derivation path is enforced by a derivation path schema.

### Schemas
Schemas are strings that contain a series of segments to define the expected pattern of a derivation path. Each segment of a schema contains a label and a type for labeling of indices. Permitted types are ***str*** for string, ***num*** for integer, and ***any*** for either. A schema can be parsed from a string using the `hdsk.Schema` function, returning the parsed schema as an *HDSchema*.

### Paths
Derivation paths are strings that define a hierarchical sequence of child key indices, descending from a master key. Each segment in the path corresponds to a level in the hierarchy, and its value may be an integer or a string. A derivation path can be parsed from a string using the `hdsk.Path` function, returning the parsed derivation path as an *HDPath*. A hash function and a schema are required to parse a derivation path.

## Generating Keys
For the generation of HD keys, keys can exist as either a master key or a child key. Master keys are derived from a given secret, and child keys are derived from a master key from a given index, or a parsed derivation path for deriving specific nodes in a hierarchy.

### Master & Child Keys
Master keys are derived from a secret using the `hdsk.Master` function, returning the derived master key as an *HDKey*. A hash function and a secret (byte slice) are required to derive a master key. Child keys are derived from a master key and an index using the `hdsk.Child` function, returning the derived child key as an *HDKey*. A hash function, pointer to a master key, and integer index are required to derive a child key.

### Nodes in a Hierarchy
Keys at specific nodes in a hierarchy descending from a master key are derived from a master key and derivation path using the `hdsk.Node` function. The master key's chain code as the secret to initialize the first key in the sequence of child key indices, with subsequent keys are derived from their corresponding index and the chain code of the previous key in the hierarchy, repeating until the target node is derived. The derived node is returned as an *HDKey*. A hash function, pointer to a master key, and HDPath are required to derive a node.

### Key Lineage
The lineage of a child key's direct descent from a master key (the child key was directly derived from the master key) can be verified using the `hdsk.Lineage` function, returning a *bool* result of the lineage verification. This verifies that a key is the direct child of a master key, using the key's fingerprint. While master keys contain their own fingerprints, the lineage of master keys cannot be verified as they lack parent keys. A hash function, and pointers to child and master keys are required to verify key lineage.

# Example Use
```go
package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/jacobhaap/go-hdsk"
)

func main() {
	// Use sha256 hash function
	h := sha256.New
	// Parse a new derivation path schema
	schema, err := hdsk.Schema("m / application: any / purpose: any / context: any / index: num")
	if err != nil {
		panic(err)
	}
	// Parse a new derivation path
	path, err := hdsk.Path(h, "m/42/0/1/0", schema)
	if err != nil {
		panic(err)
	}
	// Derive a new master key
	secret := make([]byte, 32)
	master, err := hdsk.Master(h, secret)
	if err != nil {
		panic(err)
	}
	// Derive a new child key
	child, err := hdsk.Child(h, &master, 42)
	if err != nil {
		panic(err)
	}
	// Derive a new node in a hierarchy
	node, err := hdsk.Node(h, &master, path)
	if err != nil {
		panic(err)
	}
	// Verify lineage of the child key
	lineage, err := hdsk.Lineage(h, &child, &master)
	if err != nil {
		panic(err)
	}

	// Display schema, path, keys, and lineage
	fmt.Println(`Derivation Path Schema:`, schema)
	fmt.Println(`Derivation Path:`, path)
	fmt.Println(`Master Key:`, master.Key)
	fmt.Println(`Child Key:`, child.Key)
	fmt.Println(`Node in a Hierarchy:`, node.Key)
	fmt.Println(`Child derived from Master:`, lineage)
}
```
