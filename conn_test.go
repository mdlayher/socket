package socket_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mdlayher/socket/internal/sockettest"
	"golang.org/x/net/nettest"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func TestConn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pipe nettest.MakePipe
	}{
		// Standard library plumbing.
		{
			name: "basic",
			pipe: makePipe(
				func() (net.Listener, error) {
					return sockettest.Listen(0, nil)
				},
				func(addr net.Addr) (net.Conn, error) {
					return sockettest.Dial(context.Background(), addr, nil)
				},
			),
		},
		// Our own implementations which have context cancelation support.
		{
			name: "context",
			pipe: makePipe(
				func() (net.Listener, error) {
					l, err := sockettest.Listen(0, nil)
					if err != nil {
						return nil, err
					}

					return l.Context(context.Background()), nil
				},
				func(addr net.Addr) (net.Conn, error) {
					ctx := context.Background()

					c, err := sockettest.Dial(ctx, addr, nil)
					if err != nil {
						return nil, err
					}

					return c.Context(ctx), nil
				},
			),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nettest.TestConn(t, tt.pipe)

			// Our own extensions to TestConn.
			t.Run("CloseReadWrite", func(t *testing.T) { timeoutWrapper(t, tt.pipe, testCloseReadWrite) })
		})
	}
}

func TestDialTCPNoListener(t *testing.T) {
	t.Parallel()

	// See https://github.com/mdlayher/vsock/issues/47 and
	// https://github.com/lxc/lxd/pull/9894 for context on this test.
	//
	//
	// Given a (hopefully) non-existent listener on localhost, expect
	// ECONNREFUSED.
	_, err := sockettest.Dial(context.Background(), &net.TCPAddr{
		IP:   net.IPv6loopback,
		Port: math.MaxUint16,
	}, nil)

	want := os.NewSyscallError("connect", unix.ECONNREFUSED)
	if diff := cmp.Diff(want, err); diff != "" {
		t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
	}
}

func TestDialTCPContextCanceledBefore(t *testing.T) {
	t.Parallel()

	// Context is canceled before any dialing can take place.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sockettest.Dial(ctx, &net.TCPAddr{
		IP:   net.IPv6loopback,
		Port: math.MaxUint16,
	}, nil)

	if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
	}
}

var ipTests = []struct {
	name string
	ip   netip.Addr
}{
	// It appears we can dial addresses in the documentation range and
	// connect will hang, which is perfect for this test case.
	{
		name: "IPv4",
		ip:   netip.MustParseAddr("192.0.2.1"),
	},
	{
		name: "IPv6",
		ip:   netip.MustParseAddr("2001:db8::1"),
	},
}

func TestDialTCPContextCanceledDuring(t *testing.T) {
	t.Parallel()

	for _, tt := range ipTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Context is canceled during a blocking operation but without an
			// explicit deadline passed on the context.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				time.Sleep(1 * time.Second)
				cancel()
			}()

			_, err := sockettest.Dial(ctx, &net.TCPAddr{
				IP:   tt.ip.AsSlice(),
				Port: math.MaxUint16,
			}, nil)
			if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
				t.Skipf("skipping, no outbound %s connectivity: %v", tt.name, err)
			}

			if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDialTCPContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	for _, tt := range ipTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Dialing is canceled after the deadline passes.
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			_, err := sockettest.Dial(ctx, &net.TCPAddr{
				IP:   tt.ip.AsSlice(),
				Port: math.MaxUint16,
			}, nil)
			if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
				t.Skipf("skipping, no outbound %s connectivity: %v", tt.name, err)
			}

			if diff := cmp.Diff(context.DeadlineExceeded, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
			}
		})
	}
}

func TestListenerAcceptTCPContextCanceledBefore(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Context is canceled before accept can take place.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = l.Context(ctx).Accept()
	if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected accept error (-want +got):\n%s", diff)
	}
}

func TestListenerAcceptTCPContextCanceledDuring(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Context is canceled during a blocking operation but without an
	// explicit deadline passed on the context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()

	_, err = l.Context(ctx).Accept()
	if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected accept error (-want +got):\n%s", diff)
	}
}

func TestListenerAcceptTCPContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Accept is canceled after the deadline passes.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = l.Context(ctx).Accept()
	if diff := cmp.Diff(context.DeadlineExceeded, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected accept error (-want +got):\n%s", diff)
	}
}

func TestListenerConnTCPContextCanceled(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	defer l.Close()

	// Accept a single connection.
	var eg errgroup.Group
	eg.Go(func() error {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		defer c.Close()

		// Context is canceled during recvfrom.
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		b := make([]byte, 1024)
		_, _, err = c.(*sockettest.Conn).Conn.Recvfrom(ctx, b, 0)
		return err
	})

	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer c.Close()

	// Client never sends data, so we wait until ctx cancel and errgroup return.
	if diff := cmp.Diff(context.DeadlineExceeded, eg.Wait(), cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected recvfrom error (-want +got):\n%s", diff)
	}
}

func TestListenerConnTCPContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	defer l.Close()

	// Accept a single connection.
	var eg errgroup.Group
	eg.Go(func() error {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		defer c.Close()

		// Context is canceled before recvfrom can take place.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		b := make([]byte, 1024)
		_, _, err = c.(*sockettest.Conn).Conn.Recvfrom(ctx, b, 0)
		return err
	})

	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer c.Close()

	// Client never sends data, so we wait until ctx cancel and errgroup return.
	if diff := cmp.Diff(context.Canceled, eg.Wait(), cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected recvfrom error (-want +got):\n%s", diff)
	}
}

func TestFileConn(t *testing.T) {
	t.Parallel()

	// Use raw system calls to set up the socket since we assume anything being
	// passed into a FileConn is set up by another system, such as systemd's
	// socket activation.
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}

	// Bind to loopback, any available port.
	sa := &unix.SockaddrInet6{Addr: [16]byte{15: 0x01}}
	if err := unix.Bind(fd, sa); err != nil {
		t.Fatalf("failed to bind: %v", err)
	}

	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	// The socket should be ready, create a blocking file which is ready to be
	// passed into FileConn via the FileListener helper.
	f := os.NewFile(uintptr(fd), "tcpv6-listener")
	defer f.Close()

	l, err := sockettest.FileListener(f)
	if err != nil {
		t.Fatalf("failed to open file listener: %v", err)
	}
	defer l.Close()

	// To exercise the listener, attempt to accept and then immediately close a
	// single TCPv6 connection. Dial to the listener from the main goroutine and
	// wait for everything to finish.
	var eg errgroup.Group
	eg.Go(func() error {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}

		_ = c.Close()
		return nil
	})

	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	_ = c.Close()

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to wait for listener goroutine: %v", err)
	}
}

// Use our TCP net.Listener and net.Conn implementations backed by *socket.Conn
// and run compliance tests with nettest.TestConn.
//
// This nettest.MakePipe function is adapted from nettest's own tests:
// https://github.com/golang/net/blob/master/nettest/conntest_test.go
//
// Copyright 2016 The Go Authors. All rights reserved. Use of this source
// code is governed by a BSD-style license that can be found in the LICENSE
// file.
func makePipe(
	listen func() (net.Listener, error),
	dial func(addr net.Addr) (net.Conn, error),
) nettest.MakePipe {
	return func() (c1, c2 net.Conn, stop func(), err error) {
		ln, err := listen()
		if err != nil {
			return nil, nil, nil, err
		}

		// Start a connection between two endpoints.
		var err1, err2 error
		done := make(chan bool)
		go func() {
			c2, err2 = ln.Accept()
			close(done)
		}()
		c1, err1 = dial(ln.Addr())
		<-done

		stop = func() {
			if err1 == nil {
				c1.Close()
			}
			if err2 == nil {
				c2.Close()
			}
			ln.Close()
		}

		switch {
		case err1 != nil:
			stop()
			return nil, nil, nil, err1
		case err2 != nil:
			stop()
			return nil, nil, nil, err2
		default:
			return c1, c2, stop, nil
		}
	}
}

// Copied from x/net/nettest, pending acceptance of:
// https://go-review.googlesource.com/c/net/+/372815
type connTester func(t *testing.T, c1, c2 net.Conn)

func timeoutWrapper(t *testing.T, mp nettest.MakePipe, f connTester) {
	t.Helper()
	c1, c2, stop, err := mp()
	if err != nil {
		t.Fatalf("unable to make pipe: %v", err)
	}
	var once sync.Once
	defer once.Do(func() { stop() })
	timer := time.AfterFunc(time.Minute, func() {
		once.Do(func() {
			t.Error("test timed out; terminating pipe")
			stop()
		})
	})
	defer timer.Stop()
	f(t, c1, c2)
}

// testCloseReadWrite tests that net.Conns which also implement the optional
// CloseRead and CloseWrite methods can be half-closed correctly.
func testCloseReadWrite(t *testing.T, c1, c2 net.Conn) {
	// TODO(mdlayher): investigate why Mac/Windows errors are so different.
	if runtime.GOOS != "linux" {
		t.Skip("skipping, not supported on non-Linux platforms")
	}

	type closerConn interface {
		net.Conn
		CloseRead() error
		CloseWrite() error
	}

	cc1, ok1 := c1.(closerConn)
	cc2, ok2 := c2.(closerConn)
	if !ok1 || !ok2 {
		// Both c1 and c2 must implement closerConn to proceed.
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	go func() {
		defer wg.Done()

		// Writing succeeds at first but should result in a permanent "broken
		// pipe" error after closing the write side of the net.Conn.
		b := make([]byte, 64)
		if err := chunkedCopy(cc1, bytes.NewReader(b)); err != nil {
			t.Errorf("unexpected initial cc1.Write error: %v", err)
		}
		if err := cc1.CloseWrite(); err != nil {
			t.Errorf("unexpected cc1.CloseWrite error: %v", err)
		}
		_, err := cc1.Write(b)
		if nerr, ok := err.(net.Error); !ok || nerr.Timeout() {
			t.Errorf("unexpected final cc1.Write error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()

		// Reading succeeds at first but should result in an EOF error after
		// closing the read side of the net.Conn.
		if err := chunkedCopy(io.Discard, cc2); err != nil {
			t.Errorf("unexpected initial cc2.Read error: %v", err)
		}
		if err := cc2.CloseRead(); err != nil {
			t.Errorf("unexpected cc2.CloseRead error: %v", err)
		}
		if _, err := cc2.Read(make([]byte, 64)); err != io.EOF {
			t.Errorf("unexpected final cc2.Read error: %v", err)
		}
	}()
}

// chunkedCopy copies from r to w in fixed-width chunks to avoid
// causing a Write that exceeds the maximum packet size for packet-based
// connections like "unixpacket".
// We assume that the maximum packet size is at least 1024.
func chunkedCopy(w io.Writer, r io.Reader) error {
	b := make([]byte, 1024)
	_, err := io.CopyBuffer(struct{ io.Writer }{w}, struct{ io.Reader }{r}, b)
	return err
}
