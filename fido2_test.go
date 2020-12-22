package libfido2_test

import (
	"log"
	"testing"
	"time"

	"github.com/keys-pub/go-libfido2"
	"github.com/pkg/errors"
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

func TestDeviceAssertionCancel(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	require.NoError(t, err)
	if len(locs) == 0 {
		t.Skip("No devices")
	}

	t.Logf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		log.Fatal(err)
	}

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)
	salt := libfido2.RandBytes(32)
	pin := "12345"

	t.Logf("Make credential\n")
	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: "keys.pub",
		},
		libfido2.User{
			ID:   userID,
			Name: "gabriel",
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
		},
	)
	require.NoError(t, err)

	go func() {
		time.Sleep(time.Second * 2)
		t.Logf("Cancel")
		device.Cancel()
	}()

	_, err = device.Assertion(
		"keys.pub",
		cdh,
		[][]byte{attest.CredentialID},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:         libfido2.True,
			HMACSalt:   salt,
		},
	)
	require.EqualError(t, errors.Cause(err), "keep alive cancel")
}
