package libfido2_test

import (
	"testing"

	"github.com/keys-pub/go-libfido2"
	"github.com/stretchr/testify/require"
)

// TODO: It's important tests are run serially (a device can't handle concurrent requests).

func TestDeviceLocations(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	require.NoError(t, err)
	t.Logf("Found %d devices", len(locs))

	for _, loc := range locs {
		device, err := libfido2.NewDevice(loc.Path)
		require.NoError(t, err)
		info, err := device.Info()
		require.NoError(t, err)
		t.Logf("Info: %+v", info)
	}
}
