// Package hkdf provides an implementation of HKDF.
//
// This implementation uses a blake2b MAC for the mac_digest.
package hkdf

import "golang.org/x/crypto/blake2b"

// mac_digest is a blake2b MAC digest for HKDF implementation.
func mac_digest(key []uint8, data []uint8) ([]uint8, error) {
	mac, err := blake2b.New(64, key) // 64 byte blake2b MAC
	if err != nil {                  // Check if 'blake2b.New' encountered an error
		return nil, err // Return error
	}
	mac.Write(data)          // Create mac of 'data'
	return mac.Sum(nil), nil // Return blake2b MAC
}

// hkdf_extract takes an IKM and optional salt to generate a cryptographic key.
// Returns a mac_digest with the salt as the key and the IKM as the message.
func hkdf_extract(ikm []uint8, salt []uint8) ([]uint8, error) {
	if salt == nil {
		salt = make([]uint8, 64) // Use zero bytes when 'salt' is nil
	}
	return mac_digest(salt, ikm) // Return mac_digest of 'salt' and 'ikm'
}

// hkdf_expand takes a PRK, 'info', and a length to generate output of a desired length.
// Repeatedly calls mac_digest using the PRK as the key and 'info' as the message.
func hkdf_expand(prk []uint8, info []uint8, length int) ([]uint8, error) {
	t := make([]uint8, 0)   // Last block
	okm := make([]uint8, 0) // Output Key Material
	i := 0                  // Counter (index)
	if info == nil {
		info = make([]uint8, 0) // Use empty uint8 slice when 'info' is undefined
	}
	for len(okm) < length {
		i++                                           // Increment counter
		input := append(append(t, info...), uint8(i)) // Append 'info' to 't', then append 'i'
		t, err := mac_digest(prk, input)              // MAC with 'prk' key and 'input' message
		if err != nil {                               // Check if 'mac_digest' encountered an error
			return nil, err // Return error
		}
		okm = append(okm, t...) // Set the output key material to 'okm' + 't'
	}
	return okm[:length], nil // Return 'okm' at the requested byte length
}

// Hkdf is an implementation of HKDF using a Blake2b MAC. Derives a key from an initial
// keying material across extract + expand steps.
func Hkdf(ikm []uint8, salt []uint8, info []uint8, length int) ([]uint8, error) {
	prk, err := hkdf_extract(ikm, salt) // Obtain 'prk' from 'hkdf_extract' step
	if err != nil {                     // Check if 'hkdf_extract' encountered an error
		return nil, err // Return error
	}
	return hkdf_expand(prk, info, length) // Return result of 'hkdf_expand' step
}
