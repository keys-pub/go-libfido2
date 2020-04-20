package main

import (
	"fmt"
	"log"

	"github.com/keys-pub/go-fido2"
)

func main() {
	devices, err := fido2.ListDevices(100)
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		fmt.Printf("Device:\n")
		fmt.Printf("  Path: %s\n", device.Path)
		fmt.Printf("  ProductID: %d\n", device.ProductID)
	}
}
