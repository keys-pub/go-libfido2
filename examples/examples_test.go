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

		hidInfo, err := fido2.CTAPHIDInfo(device)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("CTAPHIDInfo: %+v\n", hidInfo)

		info, err := fido2.GetInfo(device)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Info: %+v\n", info)
	}

	// Output:
	//
}

func ExampleMakeCredential() {
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

	cred, err := fido2.MakeCredential(
		device,
		cdh,
		fido2.RP{
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
		"", // Pin
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

func ExampleGetAssertion() {
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

	cred, err := fido2.MakeCredential(
		device,
		cdh,
		fido2.RP{
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
		"", // Pin
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

	assertion, err := fido2.GetAssertion(
		device,
		"keys.pub",
		cdh,
		cred.ID,
		&fido2.GetAssertionOpts{
			Extensions: []fido2.Extension{fido2.HMACSecret},
			UP:         fido2.True,
			HMACSalt:   salt,
		},
		"", // Pin
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

// func ExampleCredentialsInfo() {
// 	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

// 	detected, err := fido2.DetectDevices(100)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	if len(detected) == 0 {
// 		log.Println("No devices")
// 		return
// 	}

// 	log.Printf("Using device: %+v\n", detected[0])
// 	path := detected[0].Path
// 	device, err := fido2.NewDevice(path)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer device.Close()

// 	info, err := fido2.Credentials(device, "")
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Printf("Info: %+v\n", info)

// 	// Output:
// 	//
// }

func ExampleReset() {
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
	if err := fido2.Reset(device); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}

func ExampleSetPIN() {
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

	if err := fido2.SetPIN(device, "12345", ""); err != nil {
		log.Fatal(err)
	}

	// Output:
	//

}
