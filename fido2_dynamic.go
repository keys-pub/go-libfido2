// +build dynamic

package libfido2

/*
#cgo darwin LDFLAGS: -L/usr/local/lib -lfido2
#cgo darwin CFLAGS: -I/usr/local/include -I/usr/local/opt/openssl/include
*/
import "C"
