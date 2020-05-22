package libfido2

/*
#cgo linux LDFLAGS: -L/usr/lib/x86_64-linux-gnu -lfido2
#cgo linux CFLAGS: -I/usr/include/fido
#cgo windows LDFLAGS: -L${SRCDIR}/windows/lib -lfido2
#cgo windows CFLAGS: -I${SRCDIR}/windows/include
*/
import "C"
