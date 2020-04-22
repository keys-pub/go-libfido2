package fido2_test

import (
	"log"

	"github.com/keys-pub/go-fido2"
)

func ExampleDetectDevices() {
	fido2.SetLogger(fido2.NewLogger(fido2.DebugLevel))

	infos, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}

	for _, info := range infos {
		log.Printf("Device: %+v\n", info)

		device, err := fido2.NewDevice(info.Path)
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

		cborInfo, err := device.CBORData()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("CBORInfo: %+v\n", cborInfo)
	}

	// Output:
	// ???
}
