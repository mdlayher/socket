// Package sockettest implements net.Listener and net.Conn types based on
// *socket.Conn for use in the package's tests.
package sockettest

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

type listener struct {
	addr *net.TCPAddr
	c    *socket.Conn
}

// Listen creates an IPv6 TCP net.Listener backed by a *socket.Conn on the
// specified port with optional configuration.
func Listen(port int, cfg *socket.Config) (net.Listener, error) {
	c, err := socket.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0, "tcpv6-server", cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}

	// Be sure to close the Conn if any of the system calls fail before we
	// return the Conn to the caller.

	if err := c.Bind(&unix.SockaddrInet6{Port: port}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to bind: %v", err)
	}

	if err := c.Listen(unix.SOMAXCONN); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	sa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to getsockname: %v", err)
	}

	return &listener{
		addr: newTCPAddr(sa),
		c:    c,
	}, nil
}

func (l *listener) Addr() net.Addr { return l.addr }
func (l *listener) Close() error   { return l.c.Close() }
func (l *listener) Accept() (net.Conn, error) {
	// SOCK_CLOEXEC and SOCK_NONBLOCK set automatically by Accept when possible.
	c, rsa, err := l.c.Accept(0)
	if err != nil {
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		// Don't leak the Conn if the system call fails.
		_ = c.Close()
		return nil, err
	}

	return &conn{
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
		c:      c,
	}, nil
}

type conn struct {
	local, remote *net.TCPAddr
	c             *socket.Conn
}

// Dial creates an IPv6 TCP net.Conn backed by a *socket.Conn with optional
// configuration.
func Dial(addr net.Addr, cfg *socket.Config) (net.Conn, error) {
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("expected *net.TCPAddr, but got: %T", addr)
	}

	c, err := socket.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0, "tcpv6-client", cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}

	var sa unix.SockaddrInet6
	copy(sa.Addr[:], ta.IP)
	sa.Port = ta.Port

	// Be sure to close the Conn if any of the system calls fail before we
	// return the Conn to the caller.

	if err := c.Connect(&sa); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	lsa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return &conn{
		local:  newTCPAddr(lsa),
		remote: ta,
		c:      c,
	}, nil
}

func (c *conn) Close() error                       { return c.c.Close() }
func (c *conn) LocalAddr() net.Addr                { return c.local }
func (c *conn) RemoteAddr() net.Addr               { return c.remote }
func (c *conn) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.c.Read(b)
	return n, opError("read", err)
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.c.Write(b)
	return n, opError("write", err)
}

func opError(op string, err error) error {
	// This is still a bit simplistic but sufficient for nettest.TestConn.
	switch err {
	case nil:
		return nil
	case io.EOF:
		return io.EOF
	default:
		return &net.OpError{Op: op, Err: err}
	}
}

func newTCPAddr(sa unix.Sockaddr) *net.TCPAddr {
	sa6 := sa.(*unix.SockaddrInet6)
	return &net.TCPAddr{
		IP:   sa6.Addr[:],
		Port: sa6.Port,
	}
}
