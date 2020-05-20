package libfido2_test

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/keys-pub/go-libfido2"
	"github.com/stretchr/testify/require"
)

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

func TestCreateHMACSecret(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	require.NoError(t, err)
	if len(locs) == 0 {
		t.Logf("No devices")
		return
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	require.NoError(t, err)
	defer device.Close()

	cdh := bytes.Repeat([]byte{0x01}, 32)
	rpID := "keys.pub"
	pin := "12345"

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID: rpID,
		},
		libfido2.User{
			ID: libfido2.RandBytes(16),
		},
		libfido2.ES256, // Algorithm
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.True,
			// CredProtect: libfido2.CredProtectUVRequired,
		},
	)
	require.NoError(t, err)

	t.Logf("Credential ID: %s", hex.EncodeToString(attest.CredID))
}

func TestHMACSecret(t *testing.T) {
	locs, err := libfido2.DeviceLocations()
	require.NoError(t, err)
	if len(locs) == 0 {
		t.Logf("No devices")
		return
	}
	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	require.NoError(t, err)
	defer device.Close()

	cdh := bytes.Repeat([]byte{0x01}, 32)
	rpID := "keys.pub"
	pin := ""
	credID, err := hex.DecodeString("91874f4c3d580370bf5b5301130ecc034f5927d955f5399ebad267f5666c78598942d489f10d4f4780fad392eb2962d065bdd3574375e80c42218dadd199ed3ffe7deb010000")
	require.NoError(t, err)
	salt := bytes.Repeat([]byte{0x02}, 32)

	assertion, err := device.Assertion(
		rpID,
		cdh,
		credID,
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:         libfido2.False,
			UV:         libfido2.False,
			HMACSalt:   salt,
		},
	)
	require.NoError(t, err)

	// t.Logf("Secret: %s", hex.EncodeToString(assertion.HMACSecret))
	expected := "dd67d3aa73b13b7bb71ad0fe13cf8a247632a3508d7c9906ef6dc823906c3103"

	require.Equal(t, expected, hex.EncodeToString(assertion.HMACSecret))

}
