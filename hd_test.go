package hd_test

import (
	"encoding/hex"
	"testing"

	hd "github.com/jacobhaap/go-symmetric-hd"
)

// vector is a struct for a test vector.
type vector struct {
	path string
	key  string
}

// vectors are Symmetric HD test vectors.
var vectors = []vector{
	{
		path: "m/42/0/1/0",
		key:  "238cf83c3ee7c2596b38d9b93ba9f15c757dbb65870060422ecec51073019d39",
	},
	{
		path: "m/42/0/1/1",
		key:  "d174c452c402f765d6f85a360eaa91bb6386d5b2de737178fa320de4afc435cb",
	},
	{
		path: "m/42/0/1/2",
		key:  "e0dbf06dfcaeb0bc2241c111a44b1dcd11aa1a73a149a07182ff141097018791",
	},
	{
		path: "m/42/0/1/3",
		key:  "0eb21f70c0677a335546324faf382935eca4e887aa04c0169c018fecd546d22d",
	},
	{
		path: "m/42/0/1/4",
		key:  "a8505914a849a7a37e81847f539914838cd53d1501503439c0688605ce204424",
	},
	{
		path: "m/42/0/1/5",
		key:  "6baad567810839d4ccb92558f7174643a6fd8a64723bb1d49254c9a8d283441d",
	},
	{
		path: "m/42/0/1/6",
		key:  "63ea6ca6530c534756f77aa7bfbad339137230318f4e31b46bc8eb4e0c82a702",
	},
	{
		path: "m/42/0/1/7",
		key:  "cf064451fdff06a471cddf625647d230bead69436a90ec811ff4c6cf8d67a7b2",
	},
	{
		path: "m/42/0/1/8",
		key:  "f2f5a7e494f0890467e577fa8a344d4bbb1d18d30e486b5e903cf1a48bb59476",
	},
	{
		path: "m/42/0/1/9",
		key:  "1c9e5502c36d7b7ae12b233fc89cf96b983dc2b9fbc6d86658b0d5f0a56e5b61",
	},
	{
		path: "m/42/0/1/10",
		key:  "f8b16a5125d958f2a6c13d830004de7ec732213cb4f83df62f40a7af329cf213",
	},
	{
		path: "m/42/0/1/11",
		key:  "9606d6ab5fcb0efd7e1c47c8f86be621038ca8d656451a760d2b5fe3aebd24e7",
	},
	{
		path: "m/42/0/1/12",
		key:  "824e9bc3ba2d41e3f310c4359c16afd37d6132d4fdf5e60e7283538aea784edb",
	},
	{
		path: "m/42/0/1/14",
		key:  "c002c310e7e4a8b8c1750614a9933aaf5d56b11f19b367bc60d7061e9efb23fc",
	},
	{
		path: "m/42/0/1/15",
		key:  "87f6f5cecc075aae4f8c1506dc48977b2a3a8362f49af01b44bb8df229d4a168",
	},
}

// Test for SymmetricHD
// First, a schema is parsed, and a master key is derived from a secret of a hex-encoded string.
// Then, the test vectors are iterated over, for each using the derivation path to derive an HD
// key from the master key, then checking that the embedded key in the derived HD key matches the
// vector key. Finally, for each HD key derived, a child at index 42 is derived, which is then
// used to test lineage verification with the child key and parent HD key.
func TestSymmetricHd(t *testing.T) {
	str := `m / application: any / purpose: any / context: any / index: num` // Schema string
	schema, err := hd.NewPathSchema(str)                                     // Parse the schema
	if err != nil {
		t.Fatal(err)
	}
	master, err := hd.NewMasterKey(`747261636B6572706C61747A`) // Derive a master key from a hex string secret
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		path, err := schema.Parse(v.path) // Parse the vector derivation path
		if err != nil {
			t.Fatal(err)
		}
		dk, err := hd.DeriveHdKey(master, path) // Derive an HD key from the master key and path
		if err != nil {
			t.Fatal(err)
		}
		dkHex := hex.EncodeToString(dk.Key.Key) // Encode the embedded key as hex
		if dkHex != v.key {
			t.Fatalf(`mismatch for %s: expected %q, got %q`, v.path, v.key, dkHex)
		}
		child, err := dk.DeriveChild(42) // Derive a child key at index 42
		if err != nil {
			t.Fatal(err)
		}
		lineage, err := child.Lineage(dk.Key) // Verify the lineage of the child
		if err != nil {
			t.Fatal(err)
		}
		if lineage != true {
			t.Fatalf(`invalid key lineage encountered for child of %q`, dkHex)
		}
	}
}
