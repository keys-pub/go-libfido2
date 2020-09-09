package libfido2

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework IOKit /usr/local/Cellar/libfido2/1.5.0/lib/libfido2.a /usr/local/Cellar/openssl@1.1/1.1.1g/lib/libcrypto.a ${SRCDIR}/darwin/lib/libcbor.a
#cgo darwin CFLAGS: -I/usr/local/Cellar/libfido2/1.5.0/include -I/usr/local/Cellar/openssl@1.1/1.1.1g/include
*/
import "C"
