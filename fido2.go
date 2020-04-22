package fido2

/*
#cgo darwin LDFLAGS: -L/usr/local/lib -lfido2
#cgo darwin CFLAGS: -I/usr/local/include/fido -I/usr/local/opt/openssl/include
#cgo linux LDFLAGS: -L/usr/lib/x86_64-linux-gnu -lfido2
#cgo linux CFLAGS: -I/usr/include/fido
#cgo windows LDFLAGS: -L./libfido2/output/pkg/Win64/Release/v142/dynamic -lfido2
#cgo windows CFLAGS: -I./libfido2/output/pkg/include
#include <fido.h>
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"

	"github.com/pkg/errors"
)

// Device ...
type Device struct {
	dev *C.fido_dev_t
}

// DeviceInfo ...
type DeviceInfo struct {
	Path         string
	ProductID    int16
	VendorID     int16
	Manufacturer string
	Product      string
}

// HIDInfo ...
type HIDInfo struct {
	Protocol uint8
	Major    uint8
	Minor    uint8
	Build    uint8
	Flags    uint8
}

// Option ...
type Option struct {
	Name  string
	Value bool
}

// Info ...
type Info struct {
	AAGUID     []byte
	Protocols  []byte
	Extensions []string
	Versions   []string
	Options    []Option
}

// DeviceType is latest type the device supports.
type DeviceType string

const (
	// FIDO2 ...
	FIDO2 DeviceType = "fido2"
	// U2F ...
	U2F DeviceType = "u2f"
)

// NewDevice opens device at path.
func NewDevice(path string) (*Device, error) {
	dev := C.fido_dev_new()
	cErr := C.fido_dev_open(dev, C.CString(path))
	if cErr != C.FIDO_OK {
		return nil, errors.Errorf("fido_dev_open error %d", cErr)
	}
	return &Device{
		dev: dev,
	}, nil
}

// Close device.
func (d *Device) Close() error {
	if d.dev == nil {
		return errors.Errorf("already closed")
	}
	cErr := C.fido_dev_close(d.dev)
	if cErr != C.FIDO_OK {
		return errors.Errorf("fido_dev_close error %d", cErr)
	}
	C.fido_dev_free(&d.dev)
	d.dev = nil
	return nil
}

// Type ...
func (d *Device) Type() DeviceType {
	if C.fido_dev_is_fido2(d.dev) {
		return FIDO2
	}
	return U2F
}

// ForceType ...
func (d *Device) ForceType(typ DeviceType) error {
	switch typ {
	case FIDO2:
		C.fido_dev_force_fido2(d.dev)
		return nil
	case U2F:
		C.fido_dev_force_u2f(d.dev)
		return nil
	default:
		return errors.Errorf("unknown type")
	}
}

// CTAPHIDInfo ...
func (d *Device) CTAPHIDInfo() (*HIDInfo, error) {
	protocol := C.fido_dev_protocol(d.dev)
	major := C.fido_dev_major(d.dev)
	minor := C.fido_dev_minor(d.dev)
	build := C.fido_dev_build(d.dev)
	flags := C.fido_dev_flags(d.dev)

	return &HIDInfo{
		Protocol: uint8(protocol),
		Major:    uint8(major),
		Minor:    uint8(minor),
		Build:    uint8(build),
		Flags:    uint8(flags),
	}, nil
}

// GetInfo represents authenticatorGetInfo (0x04).
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorGetInfo
func GetInfo(d *Device) (*Info, error) {
	info := C.fido_cbor_info_new()
	if cErr := C.fido_dev_get_cbor_info(d.dev, info); cErr != C.FIDO_OK {
		return nil, errors.Errorf("fido_dev_get_cbor_info failed %d", cErr)
	}

	var aaguid []byte
	var protocols []byte
	var extensions []string
	var versions []string
	var options []Option

	cAAGUIDLen := C.fido_cbor_info_aaguid_len(info)
	cAAGUIDPtr := C.fido_cbor_info_aaguid_ptr(info)
	if cAAGUIDPtr != nil {
		aaguid = C.GoBytes(unsafe.Pointer(cAAGUIDPtr), C.int(cAAGUIDLen))
	}

	cProtocolsLen := C.fido_cbor_info_protocols_len(info)
	cProtocolsPtr := C.fido_cbor_info_protocols_ptr(info)
	if cProtocolsPtr != nil {
		protocols = C.GoBytes(unsafe.Pointer(cProtocolsPtr), C.int(cProtocolsLen))
	}

	cExtensionsLen := C.fido_cbor_info_extensions_len(info)
	cExtensionsPtr := C.fido_cbor_info_extensions_ptr(info)
	if cExtensionsPtr != nil {
		extensions = goStrings(C.int(cExtensionsLen), cExtensionsPtr)
	}

	cVersionsLen := C.fido_cbor_info_versions_len(info)
	cVersionsPtr := C.fido_cbor_info_versions_ptr(info)
	if cVersionsPtr != nil {
		versions = goStrings(C.int(cVersionsLen), cVersionsPtr)
	}

	cOptionsLen := C.fido_cbor_info_options_len(info)
	cOptionsNamePtr := C.fido_cbor_info_options_name_ptr(info)
	cOptionsValuePtr := C.fido_cbor_info_options_value_ptr(info)
	if cOptionsNamePtr != nil {
		names := goStrings(C.int(cOptionsLen), cOptionsNamePtr)
		values := goBools(C.int(cOptionsLen), cOptionsValuePtr)

		options = make([]Option, 0, len(names))
		for i, name := range names {
			options = append(options, Option{Name: name, Value: values[i]})
		}
	}

	C.fido_cbor_info_free(&info)

	return &Info{
		AAGUID:     aaguid,
		Protocols:  protocols,
		Versions:   versions,
		Extensions: extensions,
		Options:    options,
	}, nil
}

// RP is Relying Party.
type RP struct {
	ID   string
	Name string
}

// User ...
type User struct {
	ID          string
	Icon        string
	Name        string
	DisplayName string
}

// Attestation from MakeCredential.
type Attestation struct {
	AuthData []byte
	PubKey   []byte
	X5C      []byte
	Sig      []byte
}

// COSEAlgorithm ...
type COSEAlgorithm int

const (
	// ES256 ...
	ES256 COSEAlgorithm = -7
	// EDDSA ...
	EDDSA COSEAlgorithm = -8

	// ECDHES256 COSEAlgorithm = -25

	// RS256 ...
	RS256 COSEAlgorithm = -257
)

// MakeCredential represents authenticatorMakeCredential (0x01).
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorMakeCredential
func MakeCredential(
	d *Device,
	clientDataHash []byte,
	rp RP,
	user User,
	typ COSEAlgorithm,
	pin string) (*Attestation, error) {

	cCred := C.fido_cred_new()
	C.fido_cred_set_clientdata_hash(cCred, (*C.uchar)(&clientDataHash[0]), C.size_t(len(clientDataHash)))
	C.fido_cred_set_rp(cCred, C.CString(rp.ID), C.CString(rp.Name))
	C.fido_cred_set_user(cCred, (*C.uchar)(&[]byte(user.ID)[0]), C.size_t(len(user.ID)), C.CString(user.Name), C.CString(user.DisplayName), C.CString(user.Icon))
	C.fido_cred_set_type(cCred, C.int(typ))
	// C.fido_cred_set_extensions()

	var cPin *C.char
	if pin != "" {
		cPin = C.CString(pin)
	}
	if cErr := C.fido_dev_make_cred(d.dev, cCred, cPin); cErr != C.FIDO_OK {
		return nil, errors.Errorf("fido_dev_make_cred failed %d", cErr)
	}

	cAuthDataLen := C.fido_cred_authdata_len(cCred)
	cAuthDataPtr := C.fido_cred_authdata_ptr(cCred)
	authData := C.GoBytes(unsafe.Pointer(cAuthDataPtr), C.int(cAuthDataLen))

	cPubKeyLen := C.fido_cred_pubkey_len(cCred)
	cPubKeyPtr := C.fido_cred_pubkey_ptr(cCred)
	pubKey := C.GoBytes(unsafe.Pointer(cPubKeyPtr), C.int(cPubKeyLen))

	cX5cLen := C.fido_cred_x5c_len(cCred)
	cX5cPtr := C.fido_cred_x5c_ptr(cCred)
	x5c := C.GoBytes(unsafe.Pointer(cX5cPtr), C.int(cX5cLen))

	cSigLen := C.fido_cred_sig_len(cCred)
	cSigPtr := C.fido_cred_sig_ptr(cCred)
	sig := C.GoBytes(unsafe.Pointer(cSigPtr), C.int(cSigLen))

	attestation := &Attestation{
		AuthData: authData,
		PubKey:   pubKey,
		X5C:      x5c,
		Sig:      sig,
	}

	C.fido_cred_free(&cCred)

	return attestation, nil
}

// SetPin ...
func (d *Device) SetPin(pin string, old string) error {
	if cErr := C.fido_dev_set_pin(d.dev, C.CString(pin), C.CString(old)); cErr != C.FIDO_OK {
		return errors.Errorf("fido_dev_set_pin failed %d", cErr)
	}
	return nil
}

// Reset represents authenticatorReset.
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorReset
func Reset(d *Device) error {
	if cErr := C.fido_dev_reset(d.dev); cErr != C.FIDO_OK {
		return errors.Errorf("fido_dev_reset failed %d", cErr)
	}
	return nil
}

// RetryCount ...
func (d *Device) RetryCount() (int, error) {
	var retryCount C.int
	if cErr := C.fido_dev_get_retry_count(d.dev, &retryCount); cErr != C.FIDO_OK {
		return 0, errors.Errorf("fido_dev_get_retry_count failed %d", cErr)
	}
	return int(retryCount), nil
}

// type Assertion struct {
// 	AuthData       []byte
// 	ClientDataHash []byte
// 	HMACSecret     []byte
// 	Signature      []byte
// 	User           User
// }
// func NewAssertion() *Assertion {}

// DetectDevices detects devices.
func DetectDevices(max int) ([]*DeviceInfo, error) {
	logger.Debugf("Detect devices...")
	cMax := C.size_t(max)
	devList := C.fido_dev_info_new(cMax)
	defer C.fido_dev_info_free(&devList, cMax)

	// Get number of devices found
	var cFound C.size_t = 0
	cErr := C.fido_dev_info_manifest(
		devList,
		cMax,
		&cFound,
	)
	if cErr != C.FIDO_OK {
		return nil, errors.Errorf("fido_dev_info_manifest error %d", cErr)
	}

	logger.Debugf("Found: %d\n", cFound)

	deviceInfos := make([]*DeviceInfo, 0, int(cFound))
	for i := 0; i < int(cFound); i++ {
		devInfo := C.fido_dev_info_ptr(devList, C.size_t(i))
		if devInfo == nil {
			return nil, errors.Errorf("device info is empty")
		}

		cPath := C.fido_dev_info_path(devInfo)
		cProductID := C.fido_dev_info_product(devInfo)
		cVendorID := C.fido_dev_info_vendor(devInfo)
		cManufacturer := C.fido_dev_info_manufacturer_string(devInfo)
		cProduct := C.fido_dev_info_product_string(devInfo)

		deviceInfos = append(deviceInfos, &DeviceInfo{
			Path:         C.GoString(cPath),
			ProductID:    int16(cProductID),
			VendorID:     int16(cVendorID),
			Manufacturer: C.GoString(cManufacturer),
			Product:      C.GoString(cProduct),
		})
	}
	return deviceInfos, nil
}

func goStrings(argc C.int, argv **C.char) []string {
	length := int(argc)
	tmpslice := (*[1 << 30]*C.char)(unsafe.Pointer(argv))[:length:length]
	gostrings := make([]string, length)
	for i, s := range tmpslice {
		gostrings[i] = C.GoString(s)
	}
	return gostrings
}

func goBools(argc C.int, argv *C.bool) []bool {
	length := int(argc)
	tmpslice := (*[1 << 30]C.bool)(unsafe.Pointer(argv))[:length:length]
	gobools := make([]bool, length)
	for i, s := range tmpslice {
		gobools[i] = bool(s)
	}
	return gobools
}
