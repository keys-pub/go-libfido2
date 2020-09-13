# go-libfido2

Go wrapper for libfido2.

```go
import (
    "github.com/keys-pub/go-libfido2"
)

func ExampleDevice_Assertion() {
    locs, err := libfido2.DeviceLocations()
    if err != nil {
        log.Fatal(err)
    }
    if len(locs) == 0 {
        log.Println("No devices")
        return
    }

    log.Printf("Using device: %+v\n", locs[0])
    path := locs[0].Path
    device, err := libfido2.NewDevice(path)
    if err != nil {
        log.Fatal(err)
    }

    cdh := libfido2.RandBytes(32)
    userID := libfido2.RandBytes(32)
    salt := libfido2.RandBytes(32)
    pin := "12345"

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
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Attestation:\n")
    log.Printf("AuthData: %s\n", hex.EncodeToString(attest.AuthData))
    log.Printf("ClientDataHash: %s\n", hex.EncodeToString(attest.ClientDataHash))
    log.Printf("ID: %s\n", hex.EncodeToString(attest.CredentialID))
    log.Printf("Type: %s\n", attest.CredentialType)
    log.Printf("Sig: %s\n", hex.EncodeToString(attest.Sig))

    assertion, err := device.Assertion(
        "keys.pub",
        cdh,
        attest.CredentialID,
        pin,
        &libfido2.AssertionOpts{
            Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
            UP:         libfido2.True,
            HMACSalt:   salt,
        },
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Assertion:\n")
    log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
    log.Printf("%s\n", hex.EncodeToString(assertion.HMACSecret))
    log.Printf("%s\n", hex.EncodeToString(assertion.Sig))

    // Output:
    //
}
```

## Examples

The examples require a device.

To run an example, set FIDO2_EXAMPLES=1.

```shell
FIDO2_EXAMPLES=1 go test -v -run ExampleDeviceLocations
FIDO2_EXAMPLES=1 go test -v -run ExampleDevice_Assertion
FIDO2_EXAMPLES=1 go test -v -run ExampleDevice_Credentials
```

## Dependencies

### Linux

```shell
sudo apt install software-properties-common
sudo apt-add-repository ppa:yubico/stable
sudo apt update
sudo apt install libfido2-dev
```

### macOS

```shell
brew install libfido2
```

### Windows

```shell
scoop bucket add keys.pub https://github.com/keys-pub/scoop-bucket
scoop install libfido2
```
