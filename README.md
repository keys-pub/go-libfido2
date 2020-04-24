# go-libfido2

Go wrapper for libfido2.

```go
import (
    fido2 "github.com/keys-pub/go-libfido2"
)

...

detected, err := fido2.DetectDevices(100)
if err != nil {
    log.Fatal(err)
}
if len(detected) == 0 {
    log.Println("No devices")
    return
}

log.Printf("Using device: %+v\n", detected[0])
path := detected[0].Path
device, err := fido2.NewDevice(path)
if err != nil {
    log.Fatal(err)
}
defer device.Close()

cdh := fido2.RandBytes(32)
userID := fido2.RandBytes(32)
salt := fido2.RandBytes(32)

cred, err := fido2.MakeCredential(
    device,
    cdh,
    fido2.RP{
        ID: "keys.pub",
    },
    fido2.User{
        ID:   userID,
        Name: "gabriel",
    },
    fido2.ES256, // Algorithm
    &fido2.MakeCredentialOpts{
        Extensions: []fido2.Extension{fido2.HMACSecret},
        RK:         fido2.True,
    },
    "", // Pin
)
if err != nil {
    log.Fatal(err)
}

log.Printf("Credential:\n")
log.Printf("ID: %s\n", hex.EncodeToString(cred.ID))
log.Printf("Type: %s\n", cred.Type)
log.Printf("Sig: %s\n", hex.EncodeToString(cred.Sig))

assertion, err := fido2.GetAssertion(
    device,
    "keys.pub",
    cdh,
    cred.ID,
    &fido2.GetAssertionOpts{
        Extensions: []fido2.Extension{fido2.HMACSecret},
        UP:         fido2.True,
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
```
