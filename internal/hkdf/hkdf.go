// Package hkdf provides an implementation of HKDF.
//
// This implementation uses a blake2b MAC for the mac_digest.
package hkdf

import "golang.org/x/crypto/blake2b"

// mac_digest is a blake2b MAC digest for HKDF implementation.
func mac_digest(key []uint8, data []uint8) ([]uint8, error) {
	mac, err := blake2b.New(64, key) // Create a 64 byte blake2b MAC
	if err != nil {
		return nil, err
	}
	mac.Write(data)          // Write 'data' to the MAC
	return mac.Sum(nil), nil // Return blake2b MAC
}

// Extract takes an IKM and optional salt to generate a cryptographic key.
// Returns a mac_digest with the salt as the key and the IKM as the message.
func Extract(ikm []uint8, salt []uint8) ([]uint8, error) {
	if salt == nil {
		salt = make([]uint8, 64) // Use zero bytes when 'salt' is nil
	}
	return mac_digest(salt, ikm) // Return mac_digest of 'salt' and 'ikm'
}

// Expand takes a PRK, 'info', and a length to generate output of a desired length.
// Repeatedly calls mac_digest using the PRK as the key and 'info' as the message.
func Expand(prk []uint8, info []uint8, length int) ([]uint8, error) {
	t := make([]uint8, 0)   // Last block
	okm := make([]uint8, 0) // Output Key Material
	i := 0                  // Counter (index)
	if info == nil {
		info = make([]uint8, 0) // Use empty uint8 slice when 'info' is undefined
	}
	var err error
	for len(okm) < length {
		i++                                           // Increment counter
		input := append(append(t, info...), uint8(i)) // Append 'info' to 't', then append 'i'
		t, err = mac_digest(prk, input)               // MAC with 'prk' key and 'input' message
		if err != nil {
			return nil, err
		}
		okm = append(okm, t...) // Set the output key material to 'okm' + 't'
	}
	return okm[:length], nil // Return the OKM at the requested byte length
}

// New is an implementation of HKDF using a blake2b MAC. Derives a key from an initial
// keying material across extract + expand operation.
func New(ikm []uint8, salt []uint8, info []uint8, length int) ([]uint8, error) {
	prk, err := Extract(ikm, salt) // Obtain PRK from Extract operation
	if err != nil {
		return nil, err
	}
	return Expand(prk, info, length) // Return result of Expand operation
}
