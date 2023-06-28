package libfido2

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework IOKit /usr/local/lib/libfido2.a /usr/local/opt/openssl@3/lib/libcrypto.a ${SRCDIR}/darwin/amd64/lib/libcbor.a
#cgo darwin CFLAGS: -I/usr/local/opt/libfido2/include -I/usr/local/opt/openssl@3/include
*/
import "C"
