package fido2_test

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	fido2 "github.com/keys-pub/go-libfido2"
)

func ExampleDetectDevices() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range detected {
		log.Printf("Device: %+v\n", d)
		device, err := fido2.NewDevice(d.Path)
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

		info, err := device.GetInfo()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Info: %+v\n", info)
	}

	// Output:
	//
}

func ExampleDevice_MakeCredential() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := fido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	cdh := fido2.RandBytes(32)
	userID := fido2.RandBytes(32)

	cred, err := device.MakeCredential(
		cdh,
		fido2.RelyingParty{
			ID:   "keys.pub",
			Name: "keys.pub",
		},
		fido2.User{
			ID:          userID,
			Name:        "gabriel",
			DisplayName: "Gabriel",
		},
		fido2.ES256, // Algorithm
		nil,
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Credential:\n")
	log.Printf("AuthData: %s\n", spew.Sdump(cred.AuthData))
	log.Printf("ClientDataHash: %s\n", spew.Sdump(cred.ClientDataHash))
	log.Printf("ID: %s\n", spew.Sdump(cred.ID))
	log.Printf("Type: %d\n", cred.Type)
	log.Printf("Sig: %s\n", spew.Sdump(cred.Sig))

	// Output:
	//
}

func ExampleDevice_Assertion() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := fido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	cdh := fido2.RandBytes(32)
	userID := fido2.RandBytes(32)
	salt := fido2.RandBytes(32)

	cred, err := device.MakeCredential(
		cdh,
		fido2.RelyingParty{
			ID: "keys.pub",
		},
		fido2.User{
			ID:   userID,
			Name: "gabriel",
		},
		fido2.ES256, // Algorithm
		&fido2.MakeCredentialOpts{
			Extensions: []fido2.Extension{fido2.HMACSecret},
			RK:         fido2.True,
		},
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Credential:\n")
	// log.Printf("AuthData: %s\n", spew.Sdump(cred.AuthData))
	// log.Printf("ClientDataHash: %s\n", spew.Sdump(cred.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
	log.Printf("Type: %s\n", cred.Type)
	log.Printf("Sig: %s\n", spew.Sdump(cred.Sig))

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		cred.ID,
		&fido2.AssertionOpts{
			Extensions: []fido2.Extension{fido2.HMACSecret},
			UP:         fido2.True,
			HMACSalt:   salt,
		},
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("%s\n", spew.Sdump(assertion.AuthData))
	log.Printf("%s\n", spew.Sdump(assertion.HMACSecret))
	log.Printf("%s\n", spew.Sdump(assertion.Sig))
	// log.Printf("%+v\n", assertion.User)

	// Output:
	//
}

func ExampleDevice_Credentials() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := fido2.NewDevice(path)
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
			// log.Printf("AuthData: %s\n", hex.EncodeToString(cred.AuthData))
			// log.Printf("ClientDataHash: %s\n", hex.EncodeToString(cred.ClientDataHash))
			// log.Printf("Sig: %s\n", hex.EncodeToString(cred.Sig))
			log.Printf("\n")
		}
	}

	// Output:
	//
}

func ExampleDevice_Reset() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	if os.Getenv("RESET_ALLOWED") != "1" {
		log.Fatal("only runs if RESET_ALLOWED")
	}

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := fido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	log.Printf("Resetting: %+v\n", detected[0])
	if err := device.Reset(); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}

func ExampleDevice_SetPIN() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := fido2.NewDevice(path)
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
