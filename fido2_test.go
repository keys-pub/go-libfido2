package libfido2_test

import (
	"testing"
	"time"

	"github.com/keys-pub/go-libfido2"
	"github.com/stretchr/testify/require"
)

// TODO: It's important tests are run serially (a device can't handle concurrent requests).

func TestDevices(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	require.NoError(t, err)
	t.Logf("Found %d devices", len(locs))

	for _, loc := range locs {
		device, err := libfido2.NewDevice(loc.Path)
		require.NoError(t, err)

		isFIDO2, err := device.IsFIDO2()
		require.NoError(t, err)
		if !isFIDO2 {
			continue
		}

		typ, err := device.Type()
		require.NoError(t, err)
		require.Equal(t, libfido2.FIDO2, typ)

		// Testing info twice (hid_osx issues in the past caused a delayed 2nd request to fail).
		info, err := device.Info()
		require.NoError(t, err)
		time.Sleep(time.Millisecond * 100)

		info, err = device.Info()
		require.NoError(t, err)
		t.Logf("Info: %+v", info)
	}
}
