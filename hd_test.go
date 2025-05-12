package hd_test

import (
	"testing"

	hd "github.com/jacobhaap/go-symmetric-hd"
)

var err error
var schema *hd.PathSchema
var path hd.Path
var master *hd.Key
var child *hd.Key

func TestNewPathSchema(t *testing.T) {
	str := `m / application: any / purpose: any / context: any / index: num`
	schema, err = hd.NewPathSchema(str)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParse(t *testing.T) {
	path, err = schema.Parse(`m/42/0/1/0`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewMasterKey(t *testing.T) {
	master, err = hd.NewMasterKey(`7265706C696372`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewChildKey(t *testing.T) {
	_, err := hd.NewChildKey(master.Key, 42)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeriveChild(t *testing.T) {
	child, err = master.DeriveChild(42)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeriveHdKey(t *testing.T) {
	_, err := hd.DeriveHdKey(master, path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLineage(t *testing.T) {
	lineage, err := child.Lineage(master.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !lineage {
		t.Fatal(`lineage returned false, expected true`)
	}
}
