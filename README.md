# Go | Symmetric HD
Symmetric HD is an implementation of Hierarchical Deterministic (HD) keys in a symmetric context. Blake2b and an HKDF-Blake2b implementation are utilized as the cryptographic primitives.

## HDKey Type
All keys derived by this library are of the `HDKey` type, a struct that holds the 32 byte symmetric key, the chain code, and metadata including the depth in the hierarchy, derivation path, and the key's fingerprint.
```go
type HDKey struct {
	Key         []uint8 // Key
	Code        []uint8 // Chain code
	Depth       int     // Depth in hierarchy
	Path        string  // Derivation path
	Fingerprint []uint8 // Fingerprint
}
```

# Derivation Paths
When deriving an HD key in a nested hierarchy, a derivation path is required. All derivation paths are required to follow a schema, which may defined using the `NewPathSchema` function. The function expects a ***schema*** parameter as a *string*, and returns a `PathSchema` *struct* holding the parsed schema. Schemas assign labels to indices of a derivation path, as a method to assign a purpose or context. Labels are typed, as either a string `str`, integer `num`, or `any` for either of the two. A derivation path schema must always begin with `m` to designate the master key. Schemas are divided into segments, with each segment containing a label and type as `label: type`, and not exceeding 256 segments in the schema (including the master key segment).

*Default schema:*
```
m / application: any / purpose: any / context: any / index: num
```
A derivation path is parsed using a schema to enforce type and validity, parsed using the `Parse` function held in a **PathSchema** *struct* that contains a parsed schema. The function expects a ***path*** parameter as a string, and returns a *slice* of integers (*[]int*). The number of indices may not exceed the number of segments from the schema, and each index must fall in the range **0** to **2³¹-1**. When an index is provided as a string, during parsing it converts to a 32 bit integer.

*Default derivation path:*
```
m/42/0/1/0
```

# Key Derivation
Derivation of HD keys always begins from the derivation of a master key from a secret. From a master key, a child key may be derived at a selected in-range index. Child keys may also be derived from other child keys. Child key derivation always derives a key at a depth of 1 deeper in the hierarchy than the parent node. For derivation in a nested hierarchy, a master or child key combined with a derivation path derives a child key at a node in the hierarchy corresponding to the indices contained in the path.

## Master Keys
Master keys are derived from a ***secret*** using the `NewMasterKey` function. The ***secret*** parameter is expected as either a UTF-8 or hex-encoded *string*, or a *Uint8Array*. The *NewMasterKey* function returns a *struct* holding the derived master key.

## Child Keys
Child keys are derived with the `NewChildKey` function, with an HD key provided as the ***parent*** parameter, or with the `DeriveChild` function held in a *struct* that contains an HD key. Both functions expect an ***index*** parameter as either a UTF-8 or hex-encoded *string*, or a *Uint8Array*. Both functions return a *struct* holding the derived child key.

## Path-Based Key Derivation
Hierarchical deterministic keys in a nested hierarchy defined by a derivation path can be derived from a ***key*** and a ***path***, using the `DeriveHdKey` function. The ***key*** is expected as a *struct* containing an **HDKey**, and the ***path*** is expected as a parsed derivation path. The *DeriveHdKey* function returns a new child key.

## Lineage Verification
All keys, including master keys, include a fingerprint that acts as a unique identifier for the key, and can be used to verify that a key is derived from a given secret, or that it is the direct child of a parent key. The verification of key lineage is completed using the `Lineage` function held by a *struct* that contains an HD key. This function expects a ***parent*** parameter as an *HDKey*, and returns a *bool* result of the lineage verification.

## Example
```go
package main

import (
	"fmt"

	hd "github.com/jacobhaap/go-symmetric-hd"
)

func main() {
	// Define a new derivation path schema with
	str := `m / application: any / purpose: any / context: any / index: num`
	schema, err := hd.NewPathSchema(str)
	if err != nil {
		panic(err)
	}

	// Parse/validate a derivation path using the schema
	path, err := schema.Parse(`m/42/0/1/0`)
	if err != nil {
		panic(err)
	}

	// Derive a new master key from a secret
	master, err := hd.NewMasterKey(`7265706C696372`)
	if err != nil {
		panic(err)
	}

	// Derive a new child key from the master key
	child, err := master.DeriveChild(42)
	if err != nil {
		panic(err)
	}

	// Verify the lineage of the child key
	lineage, err := child.Lineage(master.Key)
	if err != nil {
		panic(err)
	}

	// Derive a key in a nested hierarchy using a derivation path
	key, err := hd.DeriveHdKey(master, path)
	if err != nil {
		panic(err)
	}

	// Display schema, path, keys, and lineage
	fmt.Println(`Path Schema:`, schema.Schema)
	fmt.Println(`Derivation Path:`, path)
	fmt.Println(`Master Key:`, master)
	fmt.Println(`Child Key:`, child)
	fmt.Println(`Lineage:`, lineage)
	fmt.Println(`HD Key:`, key)
}
```
