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

	return &Conn{
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
		c:      c,
	}, nil
}

// A contextListener passes its context into accepted Conns for cancelation.
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
	c, err := cl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return c.(*Conn).Context(cl.ctx), nil
}

// A Conn is a net.Conn which can be extended with context support.
type Conn struct {
	local, remote *net.TCPAddr
	c             *socket.Conn
}

// Dial creates an IPv6 TCP net.Conn backed by a *socket.Conn with optional
// configuration.
func Dial(addr net.Addr, cfg *socket.Config) (*Conn, error) {
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

	rsa, err := c.Connect(context.Background(), &sa)
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
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
		c:      c,
	}, nil
}

func (c *Conn) Close() error                       { return c.c.Close() }
func (c *Conn) CloseRead() error                   { return c.c.CloseRead() }
func (c *Conn) CloseWrite() error                  { return c.c.CloseWrite() }
func (c *Conn) LocalAddr() net.Addr                { return c.local }
func (c *Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *Conn) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.c.Read(b)
	return n, opError("read", err)
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.c.Write(b)
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
	n, err := cc.c.ReadContext(cc.ctx, b)
	return n, opError("read", err)
}

func (cc *contextConn) Write(b []byte) (int, error) {
	n, err := cc.c.WriteContext(cc.ctx, b)
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
