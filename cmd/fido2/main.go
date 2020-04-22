package main

import (
	"fmt"
	"log"

	"github.com/keys-pub/go-fido2"
)

func main() {
	detected, err := fido2.DetectDevices(100)
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range detected {
		fmt.Printf("Device: %+v\n", d)
	}
}
