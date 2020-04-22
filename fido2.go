package fido2

/*
#cgo darwin LDFLAGS: -L/usr/local/lib -lfido2
#cgo darwin CFLAGS: -I/usr/local/include/fido -I/usr/local/opt/openssl/include
#cgo linux LDFLAGS: -L/usr/lib/x86_64-linux-gnu -lfido2
#cgo linux CFLAGS: -I/usr/include/fido
#cgo windows LDFLAGS: -L./libfido2/output/pkg/Win64/Release/v142/dynamic -lfido2
#cgo windows CFLAGS: -I./libfido2/output/pkg/include
#include <fido.h>
#include <fido/credman.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
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

// InfoOpt ...
type InfoOpt struct {
	Name  string
	Value bool
}

// Info ...
type Info struct {
	AAGUID     []byte
	Protocols  []byte
	Extensions []string
	Versions   []string
	Options    []InfoOpt
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
		return nil, errors.Wrap(errFromCode(cErr), "failed to open")
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
		logger.Errorf("%v", errors.Wrap(errFromCode(cErr), "failed to close"))
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
func ForceType(d *Device, typ DeviceType) error {
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
func CTAPHIDInfo(d *Device) (*HIDInfo, error) {
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
	defer C.fido_cbor_info_free(&info)

	if cErr := C.fido_dev_get_cbor_info(d.dev, info); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to get info")
	}

	var aaguid []byte
	var protocols []byte
	var extensions []string
	var versions []string
	var options []InfoOpt

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

		options = make([]InfoOpt, 0, len(names))
		for i, name := range names {
			options = append(options, InfoOpt{Name: name, Value: values[i]})
		}
	}

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
	ID          []byte
	Name        string
	DisplayName string
	Icon        string
}

// Credential ...
type Credential struct {
	AuthData       []byte
	ClientDataHash []byte
	ID             []byte
	Type           COSEAlgorithm
	PubKey         []byte
	Cert           []byte
	Sig            []byte
	Format         string
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

func (c COSEAlgorithm) String() string {
	switch c {
	case ES256:
		return "es256"
	case EDDSA:
		return "eddsa"
	case RS256:
		return "rs256"
	default:
		return fmt.Sprintf("%d", c)
	}
}

// Extension ...
type Extension string

const (
	// HMACSecret is HMAC secret extension.
	// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension
	HMACSecret Extension = "hmac-secret"
)

func extensionsInt(extensions []Extension) int {
	exts := 0
	for _, extension := range extensions {
		switch extension {
		case HMACSecret:
			exts |= int(C.FIDO_EXT_HMAC_SECRET)
		}
	}
	return exts
}

// Opt ...
type Opt string

const (
	// Default is device default (omitted).
	Default Opt = "default"
	// True is enabled/yes/true option.
	True Opt = "true"
	// False is disabled/no/false option.
	False Opt = "false"
)

// MakeCredentialOpts ...
type MakeCredentialOpts struct {
	Extensions []Extension
	RK         Opt
	UV         Opt
}

func cOpt(o Opt) C.fido_opt_t {
	switch o {
	case Default, "":
		return C.FIDO_OPT_OMIT
	case True:
		return C.FIDO_OPT_TRUE
	case False:
		return C.FIDO_OPT_FALSE
	default:
		panic("invalid opt")
	}
}

// MakeCredential represents authenticatorMakeCredential (0x01).
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorMakeCredential
func MakeCredential(
	d *Device,
	clientDataHash []byte,
	rp RP,
	user User,
	typ COSEAlgorithm,
	opts *MakeCredentialOpts,
	pin string) (*Credential, error) {

	if opts == nil {
		opts = &MakeCredentialOpts{}
	}

	cCred := C.fido_cred_new()
	defer C.fido_cred_free(&cCred)
	if cErr := C.fido_cred_set_clientdata_hash(cCred, cBytes(clientDataHash), cLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set client data hash")
	}
	if cErr := C.fido_cred_set_rp(cCred, cString(rp.ID), cString(rp.Name)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set rp")
	}
	if cErr := C.fido_cred_set_user(cCred, cBytes(user.ID), cLen(user.ID), cString(user.Name), cString(user.DisplayName), cString(user.Icon)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set user")
	}
	if cErr := C.fido_cred_set_type(cCred, C.int(typ)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set type")
	}
	if cErr := C.fido_cred_set_rk(cCred, cOpt(opts.RK)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set rk")
	}
	if cErr := C.fido_cred_set_uv(cCred, cOpt(opts.UV)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set uv")
	}

	if exts := extensionsInt(opts.Extensions); exts > 0 {
		if cErr := C.fido_cred_set_extensions(cCred, C.int(exts)); cErr != C.FIDO_OK {
			return nil, errors.Wrap(errFromCode(cErr), "failed to set extensions")
		}
	}

	if cErr := C.fido_dev_make_cred(d.dev, cCred, cString(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to make credential")
	}

	cAuthDataLen := C.fido_cred_authdata_len(cCred)
	cAuthDataPtr := C.fido_cred_authdata_ptr(cCred)
	authData := C.GoBytes(unsafe.Pointer(cAuthDataPtr), C.int(cAuthDataLen))

	cClientDataHashLen := C.fido_cred_clientdata_hash_len(cCred)
	cClientDataHashPtr := C.fido_cred_clientdata_hash_ptr(cCred)
	clientDataHashOut := C.GoBytes(unsafe.Pointer(cClientDataHashPtr), C.int(cClientDataHashLen))

	cIDLen := C.fido_cred_id_len(cCred)
	cIDPtr := C.fido_cred_id_ptr(cCred)
	id := C.GoBytes(unsafe.Pointer(cIDPtr), C.int(cIDLen))

	cFormat := C.fido_cred_fmt(cCred)
	typOut := COSEAlgorithm(C.fido_cred_type(cCred))

	cPubKeyLen := C.fido_cred_pubkey_len(cCred)
	cPubKeyPtr := C.fido_cred_pubkey_ptr(cCred)
	pubKey := C.GoBytes(unsafe.Pointer(cPubKeyPtr), C.int(cPubKeyLen))

	cCertLen := C.fido_cred_x5c_len(cCred)
	cCertPtr := C.fido_cred_x5c_ptr(cCred)
	cert := C.GoBytes(unsafe.Pointer(cCertPtr), C.int(cCertLen))

	cSigLen := C.fido_cred_sig_len(cCred)
	cSigPtr := C.fido_cred_sig_ptr(cCred)
	sig := C.GoBytes(unsafe.Pointer(cSigPtr), C.int(cSigLen))

	cred := &Credential{
		AuthData:       authData,
		ClientDataHash: clientDataHashOut,
		ID:             id,
		Type:           typOut,
		PubKey:         pubKey,
		Cert:           cert,
		Sig:            sig,
		Format:         C.GoString(cFormat),
	}

	return cred, nil
}

// SetPIN ...
func SetPIN(d *Device, pin string, old string) error {
	if cErr := C.fido_dev_set_pin(d.dev, cString(pin), cString(old)); cErr != C.FIDO_OK {
		return errors.Wrap(errFromCode(cErr), "failed to set pin")
	}
	return nil
}

// Reset represents authenticatorReset.
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorReset
// The actual user-flow to perform a reset is outside the scope of the FIDO2 specification, and may therefore vary
// depending on the authenticator. Yubico authenticators will return ErrNotAllowed if a reset is issued later than 5
// seconds after power-up, and ErrActionTimeout if the user fails to confirm the reset by touching the key within 30
// seconds.
func Reset(d *Device) error {
	if cErr := C.fido_dev_reset(d.dev); cErr != C.FIDO_OK {
		return errors.Wrap(errFromCode(cErr), "failed to reset")
	}
	return nil
}

// RetryCount ...
func RetryCount(d *Device) (int, error) {
	var retryCount C.int
	if cErr := C.fido_dev_get_retry_count(d.dev, &retryCount); cErr != C.FIDO_OK {
		return 0, errors.Wrap(errFromCode(cErr), "failed to get retry count")
	}
	return int(retryCount), nil
}

// // CredentialsInfo ...
// type CredentialsInfo struct {
// 	RKExisting  int64
// 	RKRemaining int64
// }

// // Credentials ...
// func Credentials(d *Device, pin string) (*CredentialsInfo, error) {
// 	if pin == "" {
// 		return nil, errors.Errorf("pin is required")
// 	}
// 	cCredMeta := C.fido_credman_metadata_new()
// 	defer C.fido_credman_metadata_free(&cCredMeta)

// 	if cErr := C.fido_credman_get_dev_metadata(d.dev, cCredMeta, cString(pin)); cErr != C.FIDO_OK {
// 		return nil, errors.Wrap(errFromCode(cErr), "failed to get credential info")
// 	}

// 	rkExisting := int64(C.fido_credman_rk_existing(cCredMeta))
// 	rkRemaining := int64(C.fido_credman_rk_remaining(cCredMeta))

// 	return &CredentialsInfo{
// 		RKExisting:  rkExisting,
// 		RKRemaining: rkRemaining,
// 	}, nil
// }

// Assertion ...
type Assertion struct {
	AuthData   []byte
	HMACSecret []byte
	Sig        []byte
}

// GetAssertionOpts ...
type GetAssertionOpts struct {
	Extensions []Extension
	UV         Opt
	UP         Opt
	HMACSalt   []byte
}

// GetAssertion ...
func GetAssertion(
	d *Device,
	rpID string,
	clientDataHash []byte,
	credID []byte,
	opts *GetAssertionOpts,
	pin string) (*Assertion, error) {

	if opts == nil {
		opts = &GetAssertionOpts{}
	}

	cAssert := C.fido_assert_new()
	defer C.fido_assert_free(&cAssert)

	if cErr := C.fido_assert_set_rp(cAssert, cString(rpID)); cErr != C.FIDO_OK {
		return nil, errors.Wrapf(errFromCode(cErr), "failed to set assertion RP ID")
	}
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, cBytes(clientDataHash), cLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, errors.Wrapf(errFromCode(cErr), "failed to set client data hash")
	}
	if credID != nil {
		if cErr := C.fido_assert_allow_cred(cAssert, cBytes(credID), cLen(credID)); cErr != C.FIDO_OK {
			return nil, errors.Wrapf(errFromCode(cErr), "failed to set allowed credentials")
		}
	}
	if exts := extensionsInt(opts.Extensions); exts > 0 {
		if cErr := C.fido_assert_set_extensions(cAssert, C.int(exts)); cErr != C.FIDO_OK {
			return nil, errors.Wrap(errFromCode(cErr), "failed to set extensions")
		}
	}
	if cErr := C.fido_assert_set_uv(cAssert, cOpt(opts.UV)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set uv")
	}
	if cErr := C.fido_assert_set_up(cAssert, cOpt(opts.UP)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set up")
	}
	if opts.HMACSalt != nil {
		if cErr := C.fido_assert_set_hmac_salt(cAssert, cBytes(opts.HMACSalt), cLen(opts.HMACSalt)); cErr != C.FIDO_OK {
			return nil, errors.Wrapf(errFromCode(cErr), "failed to set hmac salt")
		}
	}

	// Get assertion
	if cErr := C.fido_dev_get_assert(d.dev, cAssert, cString(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrapf(errFromCode(cErr), "failed to get assertion")
	}

	// count := int(C.fido_assert_count(cAssert))
	cIdx := C.size_t(0)
	cAuthDataLen := C.fido_assert_authdata_len(cAssert, cIdx)
	cAuthDataPtr := C.fido_assert_authdata_ptr(cAssert, cIdx)
	authData := C.GoBytes(unsafe.Pointer(cAuthDataPtr), C.int(cAuthDataLen))

	cHMACLen := C.fido_assert_hmac_secret_len(cAssert, cIdx)
	cHMACPtr := C.fido_assert_hmac_secret_ptr(cAssert, cIdx)
	hmacSecret := C.GoBytes(unsafe.Pointer(cHMACPtr), C.int(cHMACLen))

	cSigLen := C.fido_assert_sig_len(cAssert, cIdx)
	cSigPtr := C.fido_assert_sig_ptr(cAssert, cIdx)
	sig := C.GoBytes(unsafe.Pointer(cSigPtr), C.int(cSigLen))

	// cUserIDLen := C.fido_assert_user_id_len(cAssert, cIdx)
	// cUserIDPtr := C.fido_assert_user_id_ptr(cAssert, cIdx)
	// userID := C.GoBytes(unsafe.Pointer(cUserIDPtr), C.int(cUserIDLen))

	// cUserName := C.fido_assert_user_name(cAssert, cIdx)
	// cUserDisplayName := C.fido_assert_user_display_name(cAssert, cIdx)
	// cUserIcon := C.fido_assert_user_icon(cAssert, cIdx)

	assertion := &Assertion{
		AuthData:   authData,
		HMACSecret: hmacSecret,
		Sig:        sig,
		// User: User{
		// 	ID:          userID,
		// 	Name:        C.GoString(cUserName),
		// 	DisplayName: C.GoString(cUserDisplayName),
		// 	Icon:        C.GoString(cUserIcon),
		// },
	}

	return assertion, nil
}

func verifyAssertion() error {
	// fido_assert_verify
	return nil
}

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
		cIdx := C.size_t(i)
		devInfo := C.fido_dev_info_ptr(devList, cIdx)
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

func cString(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func cBytes(b []byte) *C.uchar {
	return (*C.uchar)(&[]byte(b)[0])
}

func cLen(b []byte) C.size_t {
	return C.size_t(len(b))
}

// ErrCode is a generic error with code.
type ErrCode struct {
	code int
}

func (e ErrCode) Error() string {
	return fmt.Sprintf("error %d", e.code)
}

// ErrInvalidArgument if arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// ErrUserPresenceRequired is user presence required.
var ErrUserPresenceRequired = errors.New("user presence required")

// ErrTransmit if there was an error transmitting.
var ErrTransmit = errors.New("transmit error")

// ErrReceive if there was an error receiving.
var ErrReceive = errors.New("receive error")

// ErrNotAllowed if not allowed.
var ErrNotAllowed = errors.New("not allowed")

// ErrActionTimeout if action timed out.
var ErrActionTimeout = errors.New("action timed out")

// ErrPINNotSet if PIN is not set and is required for command.
var ErrPINNotSet = errors.New("pin not set")

// ErrInvalidCommand if command is not supported.
var ErrInvalidCommand = errors.New("invalid command")

// ErrInvalidCredential if credential is invalid.
var ErrInvalidCredential = errors.New("invalid credential")

func errFromCode(code C.int) error {
	switch code {
	case C.FIDO_ERR_TX:
		return ErrTransmit
	case C.FIDO_ERR_RX:
		return ErrReceive
	case C.FIDO_ERR_INVALID_ARGUMENT:
		return ErrInvalidArgument
	case C.FIDO_ERR_USER_PRESENCE_REQUIRED:
		return ErrUserPresenceRequired
	case C.FIDO_ERR_NOT_ALLOWED:
		return ErrNotAllowed
	case C.FIDO_ERR_ACTION_TIMEOUT:
		return ErrActionTimeout
	case C.FIDO_ERR_PIN_NOT_SET:
		return ErrPINNotSet
	case C.FIDO_ERR_INVALID_COMMAND:
		return ErrInvalidCommand
	case C.FIDO_ERR_INVALID_CREDENTIAL:
		return ErrInvalidCredential
	default:
		return ErrCode{code: int(code)}
	}
}
