//go:build linux

package socket

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr matches the Linux kernel's struct mmsghdr layout.
type mmsghdr struct {
	Hdr    unix.Msghdr
	Msglen uint32
	_      [4]byte // padding to 8-byte alignment
}

func recvmmsg(fd int, ps, oobs [][]byte, flags int) (n int, ns, oobns, msgFlags []int, err error) {
	vlen := len(ps)
	if vlen == 0 {
		return 0, nil, nil, nil, unix.EINVAL
	}
	if oobs != nil && len(oobs) != vlen {
		return 0, nil, nil, nil, unix.EINVAL
	}

	iovs := make([]unix.Iovec, vlen)
	msgs := make([]mmsghdr, vlen)
	for i := range vlen {
		if len(ps[i]) > 0 {
			iovs[i].Base = &ps[i][0]
			iovs[i].SetLen(len(ps[i]))
			msgs[i].Hdr.Iov = &iovs[i]
			msgs[i].Hdr.SetIovlen(1)
		}
		if oobs != nil && len(oobs[i]) > 0 {
			msgs[i].Hdr.Control = &oobs[i][0]
			msgs[i].Hdr.SetControllen(len(oobs[i]))
		}
	}

	r, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(vlen),
		uintptr(flags),
		0,
		0,
	)
	runtime.KeepAlive(ps)
	runtime.KeepAlive(oobs)
	runtime.KeepAlive(iovs)
	runtime.KeepAlive(msgs)

	if errno != 0 {
		return 0, nil, nil, nil, errnoErr(errno)
	}
	n = int(r)

	ns = make([]int, n)
	oobns = make([]int, n)
	msgFlags = make([]int, n)
	for i := range n {
		ns[i] = int(msgs[i].Msglen)
		oobns[i] = int(msgs[i].Hdr.Controllen)
		msgFlags[i] = int(msgs[i].Hdr.Flags)
	}
	return n, ns, oobns, msgFlags, nil
}

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return errEAGAIN
	case unix.EINVAL:
		return errEINVAL
	case unix.ENOENT:
		return errENOENT
	}
	return e
}
