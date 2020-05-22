package libfido2

/*
#include <fido.h>
#include <fido/credman.h>
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

// Device ...
type Device struct {
	dev *C.fido_dev_t
}

// DeviceLocation ...
type DeviceLocation struct {
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
	Value OptionValue
}

// DeviceInfo ...
type DeviceInfo struct {
	Versions   []string
	Extensions []string
	AAGUID     []byte
	Options    []Option
	Protocols  []byte
}

// DeviceType is latest type the device supports.
type DeviceType string

const (
	// UnknownDevice ...
	UnknownDevice DeviceType = ""
	// FIDO2 ...
	FIDO2 DeviceType = "fido2"
	// U2F ...
	U2F DeviceType = "u2f"
)

// RelyingParty ...
type RelyingParty struct {
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

// Attestation from MakeCredential ...
type Attestation struct {
	ClientDataHash []byte
	AuthData       []byte
	CredentialID   []byte
	CredentialType CredentialType
	PubKey         []byte
	Cert           []byte
	Sig            []byte
	Format         string
}

// Credential ...
type Credential struct {
	ID   []byte
	Type CredentialType
	User User
}

// CredentialType ...
type CredentialType int

const (
	// ES256 ...
	ES256 CredentialType = -7
	// EDDSA ...
	EDDSA CredentialType = -8

	// ECDHES256 COSEAlgorithm = -25

	// RS256 ...
	RS256 CredentialType = -257
)

func (c CredentialType) String() string {
	switch c {
	case ES256:
		return "es256"
	case EDDSA:
		return "eddsa"
	case RS256:
		return "rs256"
	default:
		return fmt.Sprintf("COSE(%d)", c)
	}
}

// Extension ...
type Extension string

const (
	// HMACSecretExtension for HMAC secret extension.
	// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension
	HMACSecretExtension Extension = "hmac-secret"
	// CredProtectExtension for credProtect extension.
	CredProtectExtension Extension = "credProtect"
)

// Assertion ...
type Assertion struct {
	AuthData   []byte
	Sig        []byte
	HMACSecret []byte
}

func extensionsInt(extensions []Extension) int {
	exts := 0
	for _, extension := range extensions {
		switch extension {
		case HMACSecretExtension:
			exts |= int(C.FIDO_EXT_HMAC_SECRET)
		case CredProtectExtension:
			exts |= int(C.FIDO_EXT_CRED_PROTECT)
		}
	}
	return exts
}

// OptionValue is value for option.
type OptionValue string

const (
	// Default is device default (omitted).
	Default OptionValue = ""
	// True is enabled/yes/true option.
	True OptionValue = "true"
	// False is disabled/no/false option.
	False OptionValue = "false"
)

// CredentialsInfo ...
type CredentialsInfo struct {
	RKExisting  int64
	RKRemaining int64
}

// DeviceLocations lists found devices.
func DeviceLocations() ([]*DeviceLocation, error) {
	logger.Debugf("Finding devices...")
	cMax := C.size_t(1000)
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

	logger.Debugf("Found %d devices\n", cFound)

	locs := make([]*DeviceLocation, 0, int(cFound))
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

		locs = append(locs, &DeviceLocation{
			Path:         C.GoString(cPath),
			ProductID:    int16(cProductID),
			VendorID:     int16(cVendorID),
			Manufacturer: C.GoString(cManufacturer),
			Product:      C.GoString(cProduct),
		})
	}
	return locs, nil
}

// NewDevice opens device at path.
func NewDevice(path string) (*Device, error) {
	if path == "" {
		return nil, errors.Errorf("empty device path")
	}
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
func (d *Device) Close() {
	if d.dev == nil {
		return
	}
	if cErr := C.fido_dev_close(d.dev); cErr != C.FIDO_OK {
		logger.Errorf("%v", errors.Wrap(errFromCode(cErr), "failed to close"))
	}
	C.fido_dev_free(&d.dev)
	d.dev = nil
}

// IsFIDO2 ...
func (d *Device) IsFIDO2() bool {
	return bool(C.fido_dev_is_fido2(d.dev))
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

// Info represents authenticatorGetInfo (0x04).
// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorGetInfo
func (d *Device) Info() (*DeviceInfo, error) {
	info := C.fido_cbor_info_new()
	defer C.fido_cbor_info_free(&info)

	if cErr := C.fido_dev_get_cbor_info(d.dev, info); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to get info")
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
			val := False
			if values[i] {
				val = True
			}
			options = append(options, Option{Name: name, Value: val})
		}
	}

	return &DeviceInfo{
		AAGUID:     aaguid,
		Protocols:  protocols,
		Versions:   versions,
		Extensions: extensions,
		Options:    options,
	}, nil
}

// MakeCredentialOpts ...
type MakeCredentialOpts struct {
	Extensions  []Extension
	RK          OptionValue
	UV          OptionValue
	CredProtect CredProtect
}

// CredProtect option if extension is supported.
type CredProtect string

const (
	// CredProtectNone if unset.
	CredProtectNone CredProtect = ""
	// CredProtectUVOptional UV optional
	CredProtectUVOptional CredProtect = "uv-optional"
	// CredProtectUVOptionalWithID UV optional with ID
	CredProtectUVOptionalWithID CredProtect = "uv-optional-with-id"
	// CredProtectUVRequired UV required
	CredProtectUVRequired CredProtect = "uv-required"
)

// MakeCredential represents authenticatorMakeCredential (0x01).
// RP, User ID and name are required by some devices, so we return an error if missing.
//
// See https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorMakeCredential
func (d *Device) MakeCredential(
	clientDataHash []byte,
	rp RelyingParty,
	user User,
	typ CredentialType,
	pin string,
	opts *MakeCredentialOpts) (*Attestation, error) {

	if opts == nil {
		opts = &MakeCredentialOpts{}
	}

	if rp.ID == "" {
		return nil, errors.Errorf("no rp id specified")
	}
	if rp.Name == "" {
		return nil, errors.Errorf("no rp name specified")
	}
	if len(user.ID) == 0 {
		return nil, errors.Errorf("no user id specified")
	}
	if user.Name == "" {
		return nil, errors.Errorf("no user name specified")
	}

	cCred := C.fido_cred_new()
	defer C.fido_cred_free(&cCred)
	if cErr := C.fido_cred_set_clientdata_hash(cCred, cBytes(clientDataHash), cLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set client data hash")
	}
	if cErr := C.fido_cred_set_rp(cCred, C.CString(rp.ID), cStringOrNil(rp.Name)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set rp")
	}
	if cErr := C.fido_cred_set_user(cCred, cBytes(user.ID), cLen(user.ID), cStringOrNil(user.Name), cStringOrNil(user.DisplayName), cStringOrNil(user.Icon)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set user")
	}
	if cErr := C.fido_cred_set_type(cCred, C.int(typ)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set type")
	}
	cRK, err := cOpt(opts.RK)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_cred_set_rk(cCred, cRK); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set rk")
	}
	cUV, err := cOpt(opts.UV)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_cred_set_uv(cCred, cUV); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set uv")
	}

	if opts.CredProtect != CredProtectNone {
		cProt, err := cCredProtect(opts.CredProtect)
		if err != nil {
			return nil, err
		}
		if cErr := C.fido_cred_set_prot(cCred, cProt); cErr != C.FIDO_OK {
			return nil, errors.Wrap(errFromCode(cErr), "failed to set prot")
		}
	}

	if exts := extensionsInt(opts.Extensions); exts > 0 {
		if cErr := C.fido_cred_set_extensions(cCred, C.int(exts)); cErr != C.FIDO_OK {
			return nil, errors.Wrap(errFromCode(cErr), "failed to set extensions")
		}
	}

	if cErr := C.fido_dev_make_cred(d.dev, cCred, cStringOrNil(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to make credential")
	}

	at, err := attestation(cCred)
	if err != nil {
		return nil, err
	}

	return at, nil
}

func attestation(cCred *C.fido_cred_t) (*Attestation, error) {
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
	typOut := CredentialType(C.fido_cred_type(cCred))

	cPubKeyLen := C.fido_cred_pubkey_len(cCred)
	cPubKeyPtr := C.fido_cred_pubkey_ptr(cCred)
	pubKey := C.GoBytes(unsafe.Pointer(cPubKeyPtr), C.int(cPubKeyLen))

	cCertLen := C.fido_cred_x5c_len(cCred)
	cCertPtr := C.fido_cred_x5c_ptr(cCred)
	cert := C.GoBytes(unsafe.Pointer(cCertPtr), C.int(cCertLen))

	cSigLen := C.fido_cred_sig_len(cCred)
	cSigPtr := C.fido_cred_sig_ptr(cCred)
	sig := C.GoBytes(unsafe.Pointer(cSigPtr), C.int(cSigLen))

	at := &Attestation{
		AuthData:       authData,
		ClientDataHash: clientDataHashOut,
		CredentialID:   id,
		CredentialType: typOut,
		PubKey:         pubKey,
		Cert:           cert,
		Sig:            sig,
		Format:         C.GoString(cFormat),
	}
	return at, nil
}

func credential(cCred *C.fido_cred_t) (*Credential, error) {
	cUserIDLen := C.fido_cred_user_id_len(cCred)
	cUserIDPtr := C.fido_cred_user_id_ptr(cCred)
	userID := C.GoBytes(unsafe.Pointer(cUserIDPtr), C.int(cUserIDLen))
	cDisplayName := C.fido_cred_display_name(cCred)
	cName := C.fido_cred_user_name(cCred)

	// cRPID := C.fido_cred_rp_id(cCred)
	// cRPName := C.fido_cred_rp_name(cCred)

	cIDLen := C.fido_cred_id_len(cCred)
	cIDPtr := C.fido_cred_id_ptr(cCred)
	id := C.GoBytes(unsafe.Pointer(cIDPtr), C.int(cIDLen))

	// cFormat := C.fido_cred_fmt(cCred)
	typOut := CredentialType(C.fido_cred_type(cCred))

	cred := &Credential{
		ID:   id,
		Type: typOut,
		User: User{
			ID:          userID,
			Name:        C.GoString(cName),
			DisplayName: C.GoString(cDisplayName),
		},
	}
	return cred, nil
}

// SetPIN ...
func (d *Device) SetPIN(pin string, old string) error {
	if cErr := C.fido_dev_set_pin(d.dev, C.CString(pin), cStringOrNil(old)); cErr != C.FIDO_OK {
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
func (d *Device) Reset() error {
	if cErr := C.fido_dev_reset(d.dev); cErr != C.FIDO_OK {
		return errors.Wrap(errFromCode(cErr), "failed to reset")
	}
	return nil
}

// RetryCount ...
func (d *Device) RetryCount() (int, error) {
	var retryCount C.int
	if cErr := C.fido_dev_get_retry_count(d.dev, &retryCount); cErr != C.FIDO_OK {
		return 0, errors.Wrap(errFromCode(cErr), "failed to get retry count")
	}
	return int(retryCount), nil
}

// AssertionOpts ...
type AssertionOpts struct {
	Extensions []Extension
	UV         OptionValue
	UP         OptionValue
	HMACSalt   []byte
}

// Assertion ...
func (d *Device) Assertion(
	rpID string,
	clientDataHash []byte,
	credentialID []byte,
	pin string,
	opts *AssertionOpts) (*Assertion, error) {

	if opts == nil {
		opts = &AssertionOpts{}
	}
	if rpID == "" {
		return nil, errors.Errorf("no rpID specified")
	}

	cAssert := C.fido_assert_new()
	defer C.fido_assert_free(&cAssert)

	if cErr := C.fido_assert_set_rp(cAssert, C.CString(rpID)); cErr != C.FIDO_OK {
		return nil, errors.Wrapf(errFromCode(cErr), "failed to set assertion RP ID")
	}
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, cBytes(clientDataHash), cLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, errors.Wrapf(errFromCode(cErr), "failed to set client data hash")
	}
	if credentialID != nil {
		if cErr := C.fido_assert_allow_cred(cAssert, cBytes(credentialID), cLen(credentialID)); cErr != C.FIDO_OK {
			return nil, errors.Wrapf(errFromCode(cErr), "failed to set allowed credentials")
		}
	}
	if exts := extensionsInt(opts.Extensions); exts > 0 {
		if cErr := C.fido_assert_set_extensions(cAssert, C.int(exts)); cErr != C.FIDO_OK {
			return nil, errors.Wrap(errFromCode(cErr), "failed to set extensions")
		}
	}
	cUV, err := cOpt(opts.UP)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_uv(cAssert, cUV); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set uv")
	}
	cUP, err := cOpt(opts.UP)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_up(cAssert, cUP); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to set up")
	}
	if opts.HMACSalt != nil {
		if cErr := C.fido_assert_set_hmac_salt(cAssert, cBytes(opts.HMACSalt), cLen(opts.HMACSalt)); cErr != C.FIDO_OK {
			return nil, errors.Wrapf(errFromCode(cErr), "failed to set hmac salt")
		}
	}

	// Get assertion
	if cErr := C.fido_dev_get_assert(d.dev, cAssert, cStringOrNil(pin)); cErr != C.FIDO_OK {
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

// CredentialsInfo ...
func (d *Device) CredentialsInfo(pin string) (*CredentialsInfo, error) {
	if pin == "" {
		return nil, errors.Errorf("pin is required")
	}

	cCredMeta := C.fido_credman_metadata_new()
	defer C.fido_credman_metadata_free(&cCredMeta)

	if cErr := C.fido_credman_get_dev_metadata(d.dev, cCredMeta, cStringOrNil(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to get credentials info")
	}

	rkExisting := int64(C.fido_credman_rk_existing(cCredMeta))
	rkRemaining := int64(C.fido_credman_rk_remaining(cCredMeta))

	return &CredentialsInfo{
		RKExisting:  rkExisting,
		RKRemaining: rkRemaining,
	}, nil
}

// Credentials ...
func (d *Device) Credentials(rpID string, pin string) ([]*Credential, error) {
	if rpID == "" {
		return nil, errors.Errorf("no rpID specified")
	}
	cRK := C.fido_credman_rk_new()
	defer C.fido_credman_rk_free(&cRK)

	if cErr := C.fido_credman_get_dev_rk(d.dev, C.CString(rpID), cRK, cStringOrNil(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to get resident key info")
	}

	count := int(C.fido_credman_rk_count(cRK))
	credentials := make([]*Credential, 0, count)
	for i := 0; i < count; i++ {
		cCred := C.fido_credman_rk(cRK, C.size_t(i))
		cred, err := credential(cCred)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, cred)
	}
	return credentials, nil
}

// RelyingParties ...
func (d *Device) RelyingParties(pin string) ([]*RelyingParty, error) {
	cRP := C.fido_credman_rp_new()
	defer C.fido_credman_rp_free(&cRP)

	if cErr := C.fido_credman_get_dev_rp(d.dev, cRP, cStringOrNil(pin)); cErr != C.FIDO_OK {
		return nil, errors.Wrap(errFromCode(cErr), "failed to get relying party info")
	}

	count := int(C.fido_credman_rp_count(cRP))
	rps := make([]*RelyingParty, 0, count)
	for i := 0; i < count; i++ {
		cRPID := C.fido_credman_rp_id(cRP, C.size_t(i))
		cRPName := C.fido_credman_rp_name(cRP, C.size_t(i))
		// TODO: fido_credman_rp_id_hash_ptr?
		rps = append(rps, &RelyingParty{
			ID:   C.GoString(cRPID),
			Name: C.GoString(cRPName),
		})
	}
	return rps, nil
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

func cStringOrNil(s string) *C.char {
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

func cOpt(o OptionValue) (C.fido_opt_t, error) {
	switch o {
	case Default:
		return C.FIDO_OPT_OMIT, nil
	case True:
		return C.FIDO_OPT_TRUE, nil
	case False:
		return C.FIDO_OPT_FALSE, nil
	default:
		return C.FIDO_OPT_OMIT, errors.Errorf("invalid cred protect")
	}
}

func cCredProtect(c CredProtect) (C.int, error) {
	switch c {
	case CredProtectUVOptional:
		return C.FIDO_CRED_PROT_UV_OPTIONAL, nil
	case CredProtectUVOptionalWithID:
		return C.FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID, nil
	case CredProtectUVRequired:
		return C.FIDO_CRED_PROT_UV_REQUIRED, nil
	default:
		return C.FIDO_CRED_PROT_UV_OPTIONAL, errors.Errorf("invalid cred protect")
	}
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

// ErrTX if there was an error transmitting.
var ErrTX = errors.New("tx error")

// ErrRX if there was an error receiving.
var ErrRX = errors.New("rx error")

// ErrNotAllowed if not allowed.
var ErrNotAllowed = errors.New("not allowed")

// ErrActionTimeout if action timed out.
var ErrActionTimeout = errors.New("action timed out")

// ErrPINNotSet if PIN is not set and is required for command.
var ErrPINNotSet = errors.New("pin not set")

// ErrInvalidCommand if command is not supported.
var ErrInvalidCommand = errors.New("invalid command")

// ErrInvalidLength if invalid length.
var ErrInvalidLength = errors.New("invalid length")

// ErrInvalidCredential if credential is invalid.
var ErrInvalidCredential = errors.New("invalid credential")

// ErrUnsupportedOption if option is unsupported.
var ErrUnsupportedOption = errors.New("unsupported option")

// ErrPinInvalid if pin is wrong.
var ErrPinInvalid = errors.New("pin invalid")

// ErrRXNotCBOR rx not CBOR.
var ErrRXNotCBOR = errors.New("rx not CBOR")

// ErrPinPolicyViolation if PIN policy violation.
var ErrPinPolicyViolation = errors.New("pin policy violation")

// ErrInternal internal error.
var ErrInternal = errors.New("internal error")

// ErrNoCredentials if no credentials.
var ErrNoCredentials = errors.New("no credentials")

// ErrPinAuthBlocked if too many PIN failures.
var ErrPinAuthBlocked = errors.New("pin auth blocked")

// ErrPinRequired if PIN is required.
var ErrPinRequired = errors.New("pin required")

// ErrMissingParameter if missing parameter.
var ErrMissingParameter = errors.New("missing parameter")

// ErrUPRequired if user presence is required.
var ErrUPRequired = errors.New("up required")

// ErrRXInvalidCBOR if receiving invalid CBOR.
var ErrRXInvalidCBOR = errors.New("rx invalid cbor")

func errFromCode(code C.int) error {
	switch code {
	case C.FIDO_ERR_TX: // -1
		return ErrTX
	case C.FIDO_ERR_RX: // -2
		return ErrRX
	case C.FIDO_ERR_INVALID_ARGUMENT: // -7
		return ErrInvalidArgument
	case C.FIDO_ERR_USER_PRESENCE_REQUIRED: // -8
		return ErrUserPresenceRequired
	case C.FIDO_ERR_INVALID_COMMAND: // 0x01
		return ErrInvalidCommand
	case C.FIDO_ERR_INVALID_LENGTH: // 0x03
		return ErrInvalidLength
	case C.FIDO_ERR_MISSING_PARAMETER:
		return ErrMissingParameter // 0x14
	case C.FIDO_ERR_NOT_ALLOWED:
		return ErrNotAllowed
	case C.FIDO_ERR_ACTION_TIMEOUT:
		return ErrActionTimeout
	case C.FIDO_ERR_PIN_NOT_SET:
		return ErrPINNotSet
	case C.FIDO_ERR_INVALID_CREDENTIAL:
		return ErrInvalidCredential
	case C.FIDO_ERR_UNSUPPORTED_OPTION:
		return ErrUnsupportedOption
	case C.FIDO_ERR_PIN_INVALID:
		return ErrPinInvalid
	case C.FIDO_ERR_RX_NOT_CBOR:
		return ErrRXNotCBOR
	case C.FIDO_ERR_INTERNAL:
		return ErrInternal
	case C.FIDO_ERR_PIN_POLICY_VIOLATION:
		return ErrPinPolicyViolation
	case C.FIDO_ERR_NO_CREDENTIALS:
		return ErrNoCredentials
	case C.FIDO_ERR_PIN_AUTH_BLOCKED:
		return ErrPinAuthBlocked
	case C.FIDO_ERR_PIN_REQUIRED:
		return ErrPinRequired
	case C.FIDO_ERR_UP_REQUIRED:
		return ErrUPRequired
	case C.FIDO_ERR_RX_INVALID_CBOR:
		return ErrRXInvalidCBOR
	default:
		return ErrCode{code: int(code)}
	}
}

// RandBytes returns random bytes of length.
func RandBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
