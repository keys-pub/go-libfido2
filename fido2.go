package fido2

/*
#cgo LDFLAGS: -L/usr/local/lib -lfido2
#cgo CFLAGS: -I/usr/local/include/fido -I/usr/local/opt/openssl/include
#include <fido.h>
#include <stdlib.h>
*/
import "C"
import "github.com/pkg/errors"

// Device ...
type Device struct {
	Path      string
	ProductID int16
}

// ListDevices detects Fido2 devices.
func ListDevices(max int) ([]*Device, error) {
	cMax := C.ulong(max)
	cDeviceList := C.fido_dev_info_new(cMax)
	defer C.fido_dev_info_free(&cDeviceList, cMax)

	// Get number of devices found
	var cFound C.size_t = 0
	cErr := C.fido_dev_info_manifest(
		cDeviceList,
		cMax,
		&cFound,
	)
	if cErr != C.FIDO_OK {
		return nil, errors.Errorf("fido_dev_info_manifest error %d", cErr)
	}

	logger.Debugf("Found: %d\n", cFound)

	devices := make([]*Device, 0, int(cFound))
	for i := 0; i < int(cFound); i++ {
		cDeviceInfo := C.fido_dev_info_ptr(cDeviceList, C.ulong(i))
		if cDeviceInfo == nil {
			return nil, errors.Errorf("device info is empty")
		}

		cPath := C.fido_dev_info_path(cDeviceInfo)
		cProductID := C.fido_dev_info_product(cDeviceInfo)

		path := C.GoString(cPath)

		devices = append(devices, &Device{
			Path:      path,
			ProductID: int16(cProductID),
		})
	}
	return devices, nil
}
