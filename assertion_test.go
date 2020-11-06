package libfido2_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/go-libfido2"
	"github.com/pkg/errors"
)

func TestAuthenticatorData(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	// cdh := libfido2.RandBytes(32)
	// userID := libfido2.RandBytes(32)
	cdh := bytes.Repeat([]byte{0x01}, 32) // libfido2.RandBytes(32)
	// userID := bytes.Repeat([]byte{0x02}, 32) // libfido2.RandBytes(32)
	pin := "12345"
	credID, _ := hex.DecodeString("f923b8f20c39cc6d5bcd4dae20f3174a51e60927ff8ebaf1500cc2a8bdbd8c0ff00e53d43162ae8bcecd7cf89832c73fc5d3d23ace700d2198c829bab6bff365")

	// attest, err := device.MakeCredential(
	// 	cdh,
	// 	libfido2.RelyingParty{
	// 		ID: "keys.pub",
	// 	},
	// 	libfido2.User{
	// 		ID:   userID,
	// 		Name: "gabriel",
	// 	},
	// 	libfido2.ES256, // Algorithm
	// 	pin,
	// 	&libfido2.MakeCredentialOpts{
	// 		// Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
	// 		// RK:         libfido2.True,
	// 	},
	// )
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("Attestation:\n")
	// log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	// log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	// log.Printf("ID: %s\n", hex.EncodeToString(attest.CredentialID))
	// log.Printf("Type: %s\n", attest.CredentialType)
	// log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))
	// credID := attest.CredentialID,

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		credID,
		pin,
		&libfido2.AssertionOpts{UP: libfido2.False},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
	log.Printf("%s\n", hex.EncodeToString(assertion.Sig))

	spew.Dump(assertion.AuthData)
	authnData, _, err := parseAuthenticatorData(assertion.AuthData)
	if err != nil {
		log.Fatal(err)
	}
	spew.Dump(authnData)
}

// AuthenticatorData represents the Web Authentication structure of the same name,
// as defined in http://w3c.github.io/webauthn/#sctn-authenticator-data
type AuthenticatorData struct {
	Raw          []byte // Complete raw authenticator data content.
	RPIDHash     []byte // SHA-256 hash of the RP ID the credential is scoped to.
	UserPresent  bool   // User is present.
	UserVerified bool   // User is verified.
	Counter      uint32 // Signature Counter.
	AAGUID       []byte // AAGUID of the authenticator (optional).
	CredentialID []byte // Identifier of a public key credential source (optional).
	// Credential   *Credential            // Algorithm and public key portion of a Relying Party-specific credential key pair (optional).
	Extensions map[string]interface{} // Extension-defined authenticator data (optional).
}

// From https://github.com/fxamacker/webauthn
func parseAuthenticatorData(data []byte) (authnData *AuthenticatorData, rest []byte, err error) {
	if len(data) < 37 {
		return nil, nil, errors.Errorf("authenticator data: unexpected EOF")
	}

	authnData = &AuthenticatorData{Raw: data}

	authnData.RPIDHash = make([]byte, 32)
	copy(authnData.RPIDHash, data)

	flags := data[32]
	authnData.UserPresent = (flags & 0x01) > 0   // UP: flags bit 0.
	authnData.UserVerified = (flags & 0x04) > 0  // UV: flags bit 2.
	credentialDataIncluded := (flags & 0x40) > 0 // AT: flags bit 6.
	extensionDataIncluded := (flags & 0x80) > 0  // ED: flags bit 7.

	authnData.Counter = binary.BigEndian.Uint32(data[33:37])

	rest = data[37:]

	if credentialDataIncluded {
		if len(rest) < 18 {
			return nil, nil, errors.Errorf("authenticator data: unexpected EOF")
		}

		authnData.AAGUID = make([]byte, 16)
		copy(authnData.AAGUID, rest)

		idLength := binary.BigEndian.Uint16(rest[16:18])

		if len(rest[18:]) < int(idLength) {
			return nil, nil, errors.Errorf("authenticator data: unexpected EOF")
		}
		authnData.CredentialID = make([]byte, idLength)
		copy(authnData.CredentialID, rest[18:])

		// if authnData.Credential, rest, err = ParseCredential(rest[18+idLength:]); err != nil {
		// 	return nil, nil, err
		// }
	}

	if extensionDataIncluded {
		return nil, nil, errors.Errorf("authenticator data extension: unsupported feature")
	}

	return
}
