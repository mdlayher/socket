//+build linux

package socket

import (
	"os"

	"golang.org/x/sys/unix"
)

// SetsockoptSockFprog wraps setsockopt(2) for unix.SockFprog values.
func (c *Conn) SetsockoptSockFprog(level, opt int, fprog *unix.SockFprog) error {
	var err error
	doErr := c.control(func(fd int) error {
		err = unix.SetsockoptSockFprog(fd, level, opt, fprog)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError("setsockopt", err)
}
