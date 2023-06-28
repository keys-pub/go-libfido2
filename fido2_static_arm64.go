package libfido2

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework IOKit /opt/homebrew/opt/libfido2/lib/libfido2.a /opt/homebrew/opt/openssl@3/lib/libcrypto.a ${SRCDIR}/darwin/arm64/lib/libcbor.a
#cgo darwin CFLAGS: -I/opt/homebrew/opt/libfido2/include -I/opt/homebrew/opt/openssl@3/include
*/
import "C"
