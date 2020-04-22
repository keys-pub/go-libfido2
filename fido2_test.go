package fido2_test

import (
	"crypto/rand"
	"log"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/go-fido2"
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

		info, err := fido2.GetInfo(device)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Info: %+v\n", info)
	}

	// Output:
	// ???
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

	cdh := randBytes(32)

	attestation, err := fido2.MakeCredential(device,
		cdh,
		fido2.RP{
			ID:   "keys.pub",
			Name: "keys.pub",
		},
		fido2.User{
			ID:          "gabriel@keys.pub",
			Name:        "gabriel",
			DisplayName: "Gabriel",
			Icon:        "?",
		},
		fido2.ES256, // Algorithm
		"",          // Pin
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Attestation:\n")
	log.Printf("%s\n", spew.Sdump(attestation.AuthData))
	log.Printf("%s\n", spew.Sdump(attestation.PubKey))
	// log.Printf("%s\n", spew.Sdump(attestation.X5C))
	log.Printf("%s\n", spew.Sdump(attestation.Sig))

	// Output:
	// ???
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
