# go-libfido2

Go wrapper for libfido2.

```go
import (
    "github.com/keys-pub/go-libfido2"
)

func ExampleDevice_Assertion() {
    detected, err := libfido2.DetectDevices(100)
    if err != nil {
        log.Fatal(err)
    }
    if len(detected) == 0 {
        log.Println("No devices")
        return
    }

    log.Printf("Using device: %+v\n", detected[0])
    path := detected[0].Path
    device, err := libfido2.NewDevice(path)
    if err != nil {
        log.Fatal(err)
    }
    defer device.Close()

    cdh := libfido2.RandBytes(32)
    userID := libfido2.RandBytes(32)
    salt := libfido2.RandBytes(32)

    cred, err := device.MakeCredential(
        cdh,
        libfido2.RelyingParty{
            ID: "keys.pub",
        },
        libfido2.User{
            ID:   userID,
            Name: "gabriel",
        },
        libfido2.ES256, // Algorithm
        &libfido2.MakeCredentialOpts{
            Extensions: []libfido2.Extension{libfido2.HMACSecret},
            RK:         libfido2.True,
        },
        "12345", // Pin
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Credential:\n")
    log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
    log.Printf("Type: %s\n", cred.Type)
    log.Printf("Sig: %s\n", hex.EncodeToString(cred.Sig))

    assertion, err := device.Assertion(
        "keys.pub",
        cdh,
        cred.ID,
        &libfido2.AssertionOpts{
            Extensions: []libfido2.Extension{libfido2.HMACSecret},
            UP:         libfido2.True,
            HMACSalt:   salt,
        },
        "", // Pin
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Assertion:\n")
    log.Printf("%s\n", hex.EncodeToString(assertion.AuthData))
    log.Printf("%s\n", hex.EncodeToString(assertion.HMACSecret))
    log.Printf("%s\n", hex.EncodeToString(assertion.Sig))
}
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
