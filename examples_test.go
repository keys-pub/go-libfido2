package libfido2_test

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"

	"github.com/keys-pub/go-libfido2"
)

func ExampleDeviceLocations() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}

	for _, loc := range locs {
		log.Printf("%+v\n", loc)
		device, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			log.Fatal(err)
		}

		hidInfo, err := device.CTAPHIDInfo()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("CTAPHIDInfo: %+v\n", hidInfo)

		info, err := device.Info()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Info: %+v\n", info)
	}

	// Output:
	//
}

func ExampleDevice_MakeCredential() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

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

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	pin := "12345"

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID:   "keys.pub",
			Name: "keys.pub",
		},
		libfido2.User{
			ID:          userID,
			Name:        "gabriel",
			DisplayName: "Gabriel",
		},
		libfido2.ES256, // Algorithm
		pin,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(attest.CredentialID))
	log.Printf("Type: %d\n", attest.CredentialType)
	log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

	// Output:
	//
}

func ExampleDevice_Assertion() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
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

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	salt := libfido2.RandBytes(32)
	pin := "12345"

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: "keys.pub",
		},
		libfido2.User{
			ID:   userID,
			Name: "gabriel",
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(attest.CredentialID))
	log.Printf("Type: %s\n", attest.CredentialType)
	log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		[][]byte{attest.CredentialID},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("AuthDataCBOR: %s\n", hex.EncodeToString(assertion.AuthDataCBOR))
	log.Printf("HMACSecret: %s\n", hex.EncodeToString(assertion.HMACSecret))
	log.Printf("Sig: %s\n", hex.EncodeToString(assertion.Sig))
	log.Printf("CredentialID: %s\n", hex.EncodeToString(assertion.CredentialID))
	log.Printf("User.ID: %s\n", hex.EncodeToString(assertion.User.ID))

	// Output:
	//
}

func ExampleDevice_Credentials() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

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

	pin := "12345"

	info, err := device.CredentialsInfo(pin)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Info: %+v\n", info)

	rps, err := device.RelyingParties(pin)
	if err != nil {
		log.Fatal(err)
	}
	for _, rp := range rps {
		log.Printf("RP{ID: %s, Name: %s}\n", rp.ID, rp.Name)
		creds, err := device.Credentials(rp.ID, pin)
		if err != nil {
			log.Fatal(err)
		}
		for _, cred := range creds {
			log.Printf("User{ID: %s, Name: %s}\n", hex.EncodeToString(cred.User.ID), cred.User.Name)
			log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
			log.Printf("Type: %s\n", cred.Type)
			log.Printf("\n")
		}
	}

	// Output:
	//
}

func ExampleDevice_Reset() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	if os.Getenv("FIDO2_EXAMPLES_RESET") != "1" {
		log.Println("only runs if FIDO2_EXAMPLES_RESET=1")
		return
	}

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

	log.Printf("Resetting: %+v\n", locs[0])
	if err := device.Reset(); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}

func ExampleDevice_SetPIN() {
	if os.Getenv("FIDO2_EXAMPLES_SET_PIN") != "1" {
		return
	}
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

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

	pin := "12345"
	if err := device.SetPIN(pin, ""); err != nil {
		log.Fatal(err)
	}

	// Output:
	//
}

func ExampleDevice_MakeCredential_hmacSecret() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	cdh := bytes.Repeat([]byte{0x01}, 32)
	rpID := "keys.pub"
	pin := "12345"

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID:   rpID,
			Name: "hmac-secret",
		},
		libfido2.User{
			ID:   libfido2.RandBytes(16),
			Name: "hmac-secret",
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
			// UV:          libfido2.True,
			// CredProtect: libfido2.CredProtectUVRequired,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Credential ID: %s\n", hex.EncodeToString(attest.CredentialID))
}

type testVector struct {
	CredentialID string
	Secret       string
}

func ExampleDevice_Assertion_hmacSecret() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatalf("No devices")
		return
	}
	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	name := locs[0].Product + "/" + locs[0].Manufacturer

	cdh := bytes.Repeat([]byte{0x01}, 32)
	rpID := "keys.pub"
	pin := "12345"

	testVectors := map[string]testVector{
		"SoloKey 4.0/SoloKeys": testVector{
			CredentialID: "91874f4c3d580370bf5b5301130ecc034f5927d955f5399ebad267f5666c78598942d489f10d4f4780fad392eb2962d065bdd3574375e80c42218dadd199ed3ffe7deb010000",
			Secret:       "dd67d3aa73b13b7bb71ad0fe13cf8a247632a3508d7c9906ef6dc823906c3103",
		},
		"Security Key by Yubico/Yubico": testVector{
			CredentialID: "c4fe75012ed137a0afcaa59ab36f0722b9b05849b2203fc4ba4f304033015eaafdbee823ee42dce88b4ae4d943926de3cc93e797004d108ed2465c675ae568e6",
			Secret:       "f3d37d52ca7a12cf05c34bd3c13ddc3288b723018697347e6ac5ea79b7d3cc83",
		},
	}

	testVector, ok := testVectors[name]
	if !ok {
		log.Fatalf("No test vector found for %s", name)
	}

	credentialID, err := hex.DecodeString(testVector.CredentialID)
	if err != nil {
		log.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x02}, 32)

	assertion, err := device.Assertion(
		rpID,
		cdh,
		[][]byte{credentialID},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			// UP:         libfido2.True, // Required for some devices
			// UV:         libfido2.True, // Required for some devices
			HMACSalt: salt,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	if testVector.Secret != hex.EncodeToString(assertion.HMACSecret) {
		log.Fatalf("Expected %s", testVector.Secret)
	}
}

func ExampleDevice_DeleteCredential() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	pin := "12345"

	info, err := device.CredentialsInfo(pin)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Info: %+v\n", info)

	rps, err := device.RelyingParties(pin)
	if err != nil {
		log.Fatal(err)
	}
	for _, rp := range rps {
		creds, err := device.Credentials(rp.ID, pin)
		if err != nil {
			log.Fatal(err)
		}
		for _, cred := range creds {
			log.Printf("Deleting: %s\n", hex.EncodeToString(cred.ID))
			if err := device.DeleteCredential(cred.ID, pin); err != nil {
				log.Fatal(err)
			}
		}
	}

	// Output:
	//
}

func ExampleDevice_BioEnrollment() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	pin := "12345"

	err = device.BioEnroll(pin)
	if err != nil {
		log.Fatal(err)
	}

	// Output:
	//
}

func ExampleDevice_BioList() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	pin := "12345"

	templates, err := device.BioList(pin)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(templates)

	// Output:
	//
}

func ExampleDevice_BioDelete() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	pin := "12345"

	templates, err := device.BioList(pin)
	if err != nil {
		log.Fatal(err)
	}

	for _, template := range templates {
		err := device.BioDelete(pin, template.ID)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Output:
	//
}

func ExampleDevice_BioSetTemplateName() {
	if os.Getenv("FIDO2_EXAMPLES") != "1" {
		return
	}
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		log.Fatal(err)
	}
	if len(locs) == 0 {
		log.Fatal("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	pin := "12345"

	templates, err := device.BioList(pin)
	if err != nil {
		log.Fatal(err)
	}

	if len(templates) == 0 {
		log.Fatal("no bio template")
		return
	}

	template := templates[0]
	newName := "newName"

	device.BioSetTemplateName(pin, template.ID, newName)

	// Output:
	//
}
