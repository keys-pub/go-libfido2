package libfido2

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework IOKit /usr/local/lib/libfido2.a /usr/local/opt/openssl@1.1/lib/libcrypto.a ${SRCDIR}/darwin/lib/libcbor.a
#cgo darwin CFLAGS: -I/usr/local/opt/libfido2/include -I/usr/local/opt/openssl@1.1/include
*/
import "C"
