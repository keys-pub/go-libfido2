package libfido2_test

import (
	"testing"

	"github.com/keys-pub/go-libfido2"
)

// See examples package instead.

func TestDeviceLocations(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Found %d devices", len(locs))
}
