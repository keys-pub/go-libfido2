package libfido2_test

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/keys-pub/go-libfido2"
)

func ExampleDetectDevices() {
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range detected {
		log.Printf("%+v\n", d)
		device, err := libfido2.NewDevice(d.Path)
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
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)

	cred, err := device.MakeCredential(
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
		nil,
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Credential:\n")
	log.Printf("AuthData: %s\n", hex.EncodeToString(cred.AuthData))
	log.Printf("ClientDataHash: %s\n", hex.EncodeToString(cred.ClientDataHash))
	log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
	log.Printf("Type: %d\n", cred.Type)
	log.Printf("Sig: %s\n", hex.EncodeToString(cred.Sig))

	// Output:
	//
}

func ExampleDevice_Assertion() {
	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	salt := libfido2.RandBytes(32)

	cred, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: "keys.pub",
		},
		libfido2.User{
			ID:   userID,
			Name: "gabriel",
		},
		libfido2.ES256, // Algorithm
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecret},
			RK:         libfido2.True,
		},
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Credential:\n")
	log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
	log.Printf("Type: %s\n", cred.Type)
	log.Printf("Sig: %s\n", hex.EncodeToString(cred.Sig))

	assertion, err := device.Assertion(
		"keys.pub",
		cdh,
		cred.ID,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecret},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
		"12345", // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Assertion:\n")
	log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
	log.Printf("%s\n", hex.EncodeToString(assertion.HMACSecret))
	log.Printf("%s\n", hex.EncodeToString(assertion.Sig))
}

func ExampleDevice_Credentials() {
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
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
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	if os.Getenv("RESET_ALLOWED") != "1" {
		log.Fatal("only runs if RESET_ALLOWED")
	}

	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
	device, err := libfido2.NewDevice(path)
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
	libfido2.SetLogger(libfido2.NewLogger(libfido2.DebugLevel))

	detected, err := libfido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}
	if len(detected) == 0 {
		log.Println("No devices")
		return
	}

	log.Printf("Using device: %+v\n", detected[0])
	path := detected[0].Path
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
