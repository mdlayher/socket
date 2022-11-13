// Package sockettest implements net.Listener and net.Conn types based on
// *socket.Conn for use in the package's tests.
package sockettest

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

// A Listener is a net.Listener which can be extended with context support.
type Listener struct {
	addr *net.TCPAddr
	c    *socket.Conn
}

// Listen creates an IPv6 TCP net.Listener backed by a *socket.Conn on the
// specified port with optional configuration. Context ctx will be passed
// to accept and accepted connections.
func Listen(port int, cfg *socket.Config) (*Listener, error) {
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

	return &Listener{
		addr: newTCPAddr(sa),
		c:    c,
	}, nil
}

// FileListener creates an IPv6 TCP net.Listener backed by a *socket.Conn from
// the input file.
func FileListener(f *os.File) (*Listener, error) {
	c, err := socket.FileConn(f, "tcpv6-server")
	if err != nil {
		return nil, fmt.Errorf("failed to open file conn: %v", err)
	}

	sa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to getsockname: %v", err)
	}

	return &Listener{
		addr: newTCPAddr(sa),
		c:    c,
	}, nil
}

func (l *Listener) Addr() net.Addr { return l.addr }
func (l *Listener) Close() error   { return l.c.Close() }
func (l *Listener) Accept() (net.Conn, error) {
	// SOCK_CLOEXEC and SOCK_NONBLOCK set automatically by Accept when possible.
	c, rsa, err := l.c.Accept(context.Background(), 0)
	if err != nil {
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		// Don't leak the Conn if the system call fails.
		_ = c.Close()
		return nil, err
	}

	return &Conn{
		Conn:   c,
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
	}, nil
}

// A contextListener passes its context into Accept and accepted Conns for
// cancelation.
type contextListener struct {
	ctx context.Context
	*Listener
}

func (l *Listener) Context(ctx context.Context) net.Listener {
	return &contextListener{
		ctx:      ctx,
		Listener: l,
	}
}

func (cl *contextListener) Accept() (net.Conn, error) {
	c, rsa, err := cl.c.Accept(cl.ctx, 0)
	if err != nil {
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		// Don't leak the Conn if the system call fails.
		_ = c.Close()
		return nil, err
	}

	cc := &Conn{
		Conn:   c,
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
	}

	return cc.Context(cl.ctx), nil
}

// A Conn is a net.Conn which can be extended with context support.
type Conn struct {
	Conn          *socket.Conn
	local, remote *net.TCPAddr
}

// Dial creates an IPv4 or IPv6 TCP net.Conn backed by a *socket.Conn with
// optional configuration.
func Dial(ctx context.Context, addr net.Addr, cfg *socket.Config) (*Conn, error) {
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("expected *net.TCPAddr, but got: %T", addr)
	}

	var (
		family int
		name   string
		sa     unix.Sockaddr
	)

	if ta.IP.To16() != nil && ta.IP.To4() == nil {
		// IPv6.
		family = unix.AF_INET6
		name = "tcpv6-client"

		var sa6 unix.SockaddrInet6
		copy(sa6.Addr[:], ta.IP)
		sa6.Port = ta.Port

		sa = &sa6
	} else {
		// IPv4.
		family = unix.AF_INET
		name = "tcpv4-client"

		var sa4 unix.SockaddrInet4
		copy(sa4.Addr[:], ta.IP.To4())
		sa4.Port = ta.Port

		sa = &sa4
	}

	c, err := socket.Socket(family, unix.SOCK_STREAM, 0, name, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}

	// Be sure to close the Conn if any of the system calls fail before we
	// return the Conn to the caller.

	rsa, err := c.Connect(ctx, sa)
	if err != nil {
		_ = c.Close()
		// Don't wrap, we want the raw error for tests.
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return &Conn{
		Conn:   c,
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
	}, nil
}

func (c *Conn) Close() error                       { return c.Conn.Close() }
func (c *Conn) CloseRead() error                   { return c.Conn.CloseRead() }
func (c *Conn) CloseWrite() error                  { return c.Conn.CloseWrite() }
func (c *Conn) LocalAddr() net.Addr                { return c.local }
func (c *Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *Conn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, opError("read", err)
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, opError("write", err)
}

// A contextConn passes its context into a Conn for cancelation.
type contextConn struct {
	ctx context.Context
	*Conn
}

func (c *Conn) Context(ctx context.Context) net.Conn {
	return &contextConn{
		ctx:  ctx,
		Conn: c,
	}
}

func (cc *contextConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Conn.ReadContext(cc.ctx, b)
	return n, opError("read", err)
}

func (cc *contextConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Conn.WriteContext(cc.ctx, b)
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
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: sa.Port,
		}
	case *unix.SockaddrInet6:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: sa.Port,
		}
	}

	panic("unknown address family")
}
