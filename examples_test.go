package libfido2_test

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/keys-pub/go-libfido2"
)

func ExampleDeviceLocations() {
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
		defer device.Close()

		log.Printf("Type: %s\n", device.Type())

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
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
	defer device.Close()

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)

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
		"12345",        // Pin
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(attest.CredID))
	log.Printf("Type: %d\n", attest.CredType)
	log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

	// Output:
	//
}

func ExampleDevice_Assertion() {
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
	defer device.Close()

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	salt := libfido2.RandBytes(32)

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
		"12345",        // Pin
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecret},
			RK:         libfido2.True,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(attest.CredID))
	log.Printf("Type: %s\n", attest.CredType)
	log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		attest.CredID,
		"12345", // Pin
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecret},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
	log.Printf("%s\n", hex.EncodeToString(assertion.HMACSecret))
	log.Printf("%s\n", hex.EncodeToString(assertion.Sig))

	// Output:
	//
}

func ExampleDevice_Credentials() {
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
	defer device.Close()

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
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
	defer device.Close()

	log.Printf("Resetting: %+v\n", locs[0])
	if err := device.Reset(); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}

func ExampleDevice_SetPIN() {
	if os.Getenv("FIDO2_EXAMPLES") == "" {
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
	defer device.Close()

	if err := device.SetPIN("12345", ""); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}
