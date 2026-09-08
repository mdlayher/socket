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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mdlayher/socket"
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

func TestListenerAcceptTCPContextCanceledDuringWithDeadline(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Context carries both a distant deadline and is canceled early during a
	// blocking operation. Cancelation must be honored immediately rather than
	// waiting for the deadline to expire.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = l.Context(ctx).Accept()
	elapsed := time.Since(start)

	if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected accept error (-want +got):\n%s", diff)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("accept took %v to observe cancelation, expected immediate return", elapsed)
	}

	// The forced wakeup must not leave a stale deadline armed on the socket.
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = l.Context(ctx).Accept()
	if diff := cmp.Diff(context.DeadlineExceeded, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected second accept error (-want +got):\n%s", diff)
	}
}

func TestListenerAcceptTCPContextBackground(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// A context which can never be canceled must still allow the operation
	// to complete normally.
	var eg errgroup.Group
	eg.Go(func() error {
		c, err := l.Context(context.Background()).Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		return c.Close()
	})

	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer c.Close()

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to accept with background context: %v", err)
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

func TestListenerConnTCPContextCanceledDuringWithDeadline(t *testing.T) {
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

		// Context carries both a distant deadline and is canceled early
		// during recvmsg. Cancelation must be honored immediately rather than
		// waiting for the deadline to expire.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		b := make([]byte, 1024)
		_, _, _, _, err = c.(*sockettest.Conn).Conn.Recvmsg(ctx, b, nil, 0)
		elapsed := time.Since(start)

		if diff := cmp.Diff(context.Canceled, err, cmpopts.EquateErrors()); diff != "" {
			return fmt.Errorf("unexpected recvmsg error (-want +got):\n%s", diff)
		}
		if elapsed > 5*time.Second {
			return fmt.Errorf("recvmsg took %v to observe cancelation, expected immediate return", elapsed)
		}

		// The forced wakeup must not leave a stale deadline armed on the
		// socket.
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		_, _, _, _, err = c.(*sockettest.Conn).Conn.Recvmsg(ctx, b, nil, 0)
		if diff := cmp.Diff(context.DeadlineExceeded, err, cmpopts.EquateErrors()); diff != "" {
			return fmt.Errorf("unexpected second recvmsg error (-want +got):\n%s", diff)
		}

		return nil
	})

	c, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer c.Close()

	// Client never sends data, so we wait until ctx cancel and errgroup return.
	if err := eg.Wait(); err != nil {
		t.Fatal(err)
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

func TestConnReadFuncWriteFunc(t *testing.T) {
	t.Parallel()

	c1, c2 := socketPair(t)
	ctx := context.Background()

	// A write to an idle socket completes on the first call.
	want := []byte("hello world")
	var writes int
	err := c1.WriteFunc(ctx, "write", func(fd int) error {
		writes++
		_, err := unix.Write(fd, want)
		return err
	})
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if diff := cmp.Diff(1, writes); diff != "" {
		t.Fatalf("unexpected number of write calls (-want +got):\n%s", diff)
	}

	// Data is already available so the read completes on the first call.
	var (
		b     = make([]byte, 64)
		n     int
		reads int
	)

	err = c2.ReadFunc(ctx, "read", func(fd int) error {
		reads++
		var err error
		n, err = unix.Read(fd, b)
		return err
	})
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if diff := cmp.Diff(1, reads); diff != "" {
		t.Fatalf("unexpected number of read calls (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(want, b[:n]); diff != "" {
		t.Fatalf("unexpected read bytes (-want +got):\n%s", diff)
	}
}

func TestConnReadFuncWriteFuncError(t *testing.T) {
	t.Parallel()

	c1, _ := socketPair(t)
	ctx := context.Background()

	// Errors other than EAGAIN/EINTR/EINPROGRESS complete the operation
	// immediately and are wrapped with the operation name.
	var calls int
	err := c1.ReadFunc(ctx, "readop", func(_ int) error {
		calls++
		return unix.EINVAL
	})
	checkSyscallError(t, "readop", unix.EINVAL, err)
	if diff := cmp.Diff(1, calls); diff != "" {
		t.Fatalf("unexpected number of read calls (-want +got):\n%s", diff)
	}

	calls = 0
	err = c1.WriteFunc(ctx, "writeop", func(_ int) error {
		calls++
		return unix.EPERM
	})
	checkSyscallError(t, "writeop", unix.EPERM, err)
	if diff := cmp.Diff(1, calls); diff != "" {
		t.Fatalf("unexpected number of write calls (-want +got):\n%s", diff)
	}
}

func TestConnReadFuncEAGAINRetry(t *testing.T) {
	t.Parallel()

	c1, c2 := socketPair(t)

	// The socket is idle, so the first read reports EAGAIN and ReadFunc must
	// wait for readiness and retry once the peer writes.
	var (
		b     = make([]byte, 64)
		n     int
		reads atomic.Int32
		eg    errgroup.Group
	)

	attempted, signal := firstCall()
	eg.Go(func() error {
		return c2.ReadFunc(context.Background(), "read", func(fd int) error {
			reads.Add(1)
			var err error
			n, err = unix.Read(fd, b)
			signal()
			return err
		})
	})

	// Wait for the first EAGAIN attempt before making the socket readable.
	<-attempted

	want := []byte("hello world")
	if _, err := c1.WriteContext(context.Background(), want); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if reads.Load() < 2 {
		t.Fatalf("expected at least two read calls, but got: %d", reads.Load())
	}

	if diff := cmp.Diff(want, b[:n]); diff != "" {
		t.Fatalf("unexpected read bytes (-want +got):\n%s", diff)
	}
}

func TestConnWriteFuncEAGAINRetry(t *testing.T) {
	t.Parallel()

	c1, c2 := socketPair(t)

	// Keep the buffers small so they fill quickly.
	if err := c1.SetWriteBuffer(4096); err != nil {
		t.Fatalf("failed to set write buffer: %v", err)
	}

	if err := c2.SetReadBuffer(4096); err != nil {
		t.Fatalf("failed to set read buffer: %v", err)
	}

	fillWriteBuffer(t, c1)

	// The kernel buffers are full, so the first write reports EAGAIN and
	// WriteFunc must wait for readiness and retry once the peer drains data.
	var (
		writes atomic.Int32
		eg     errgroup.Group
	)

	attempted, signal := firstCall()
	eg.Go(func() error {
		return c1.WriteFunc(context.Background(), "write", func(fd int) error {
			writes.Add(1)
			_, err := unix.Write(fd, []byte("hello world"))
			signal()
			return err
		})
	})

	// Wait for the first EAGAIN attempt before draining the peer.
	<-attempted

	// Drain the peer until the writer completes.
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 64*1024)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c2.ReadContext(ctx, b)
			cancel()
			if err != nil {
				return
			}
		}
	}()

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	if writes.Load() < 2 {
		t.Fatalf("expected at least two write calls, but got: %d", writes.Load())
	}

	// Closing the writer unblocks the drain goroutine with EOF.
	_ = c1.Close()
	<-done
}

func TestConnReadFuncContextCanceled(t *testing.T) {
	t.Parallel()

	_, c2 := socketPair(t)

	// Context is canceled after the first blocked read attempt; the peer
	// never writes.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempted, signal := firstCall()
	go func() {
		<-attempted
		cancel()
	}()

	b := make([]byte, 64)
	start := time.Now()
	err := c2.ReadFunc(ctx, "read", func(fd int) error {
		_, err := unix.Read(fd, b)
		signal()
		return err
	})
	elapsed := time.Since(start)

	checkSyscallError(t, "read", context.Canceled, err)
	if elapsed > 5*time.Second {
		t.Fatalf("read took %v to observe cancelation, expected immediate return", elapsed)
	}
}

func TestConnReadFuncContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	c1, c2 := socketPair(t)

	// Context deadline expires during a blocked read; the peer never writes.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	b := make([]byte, 64)
	err := c2.ReadFunc(ctx, "read", func(fd int) error {
		_, err := unix.Read(fd, b)
		return err
	})
	checkSyscallError(t, "read", context.DeadlineExceeded, err)

	// The deadline must be disarmed for the next call: with data available
	// and no context deadline, the read must succeed rather than failing
	// immediately with a stale I/O timeout.
	want := []byte("hello world")
	if _, err := c1.WriteContext(context.Background(), want); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	var n int
	err = c2.ReadFunc(context.Background(), "read", func(fd int) error {
		var err error
		n, err = unix.Read(fd, b)
		return err
	})
	if err != nil {
		t.Fatalf("failed to read after deadline: %v", err)
	}

	if diff := cmp.Diff(want, b[:n]); diff != "" {
		t.Fatalf("unexpected read bytes (-want +got):\n%s", diff)
	}

	// And a subsequent blocked read with a fresh deadline observes only the
	// new deadline.
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = c2.ReadFunc(ctx, "read", func(fd int) error {
		_, err := unix.Read(fd, b)
		return err
	})
	checkSyscallError(t, "read", context.DeadlineExceeded, err)
}

func TestConnWriteFuncContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	c1, c2 := socketPair(t)

	if err := c1.SetWriteBuffer(4096); err != nil {
		t.Fatalf("failed to set write buffer: %v", err)
	}

	if err := c2.SetReadBuffer(4096); err != nil {
		t.Fatalf("failed to set read buffer: %v", err)
	}

	fillWriteBuffer(t, c1)

	// Context deadline expires during a blocked write; the peer never reads.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := c1.WriteFunc(ctx, "write", func(fd int) error {
		_, err := unix.Write(fd, []byte("hello world"))
		return err
	})
	checkSyscallError(t, "write", context.DeadlineExceeded, err)

	// The deadline must be disarmed for the next call: a subsequent write
	// with no context deadline waits for the peer to drain rather than
	// failing immediately with a stale I/O timeout.
	var eg errgroup.Group
	attempted, signal := firstCall()
	eg.Go(func() error {
		return c1.WriteFunc(context.Background(), "write", func(fd int) error {
			_, err := unix.Write(fd, []byte("hello world"))
			signal()
			return err
		})
	})

	// Wait for the first EAGAIN attempt before draining the peer.
	<-attempted

	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 64*1024)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := c2.ReadContext(ctx, b)
			cancel()
			if err != nil {
				return
			}
		}
	}()

	if err := eg.Wait(); err != nil {
		t.Fatalf("failed to write after deadline: %v", err)
	}

	_ = c1.Close()
	<-done
}

func TestConnReadFuncWriteFuncClosed(t *testing.T) {
	t.Parallel()

	c1, _ := socketPair(t)
	if err := c1.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// After Close, neither function invokes f and both report EBADF.
	err := c1.ReadFunc(context.Background(), "read", func(_ int) error {
		panic("f must not be called after Close")
	})
	checkSyscallError(t, "read", unix.EBADF, err)

	err = c1.WriteFunc(context.Background(), "write", func(_ int) error {
		panic("f must not be called after Close")
	})
	checkSyscallError(t, "write", unix.EBADF, err)
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

// socketPair creates a pair of connected AF_UNIX stream Conns for tests. Both
// are closed when the test completes.
func socketPair(t *testing.T) (c1, c2 *socket.Conn) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("failed to create socketpair: %v", err)
	}

	c1, err = socket.New(fds[0], "unix-1")
	if err != nil {
		t.Fatalf("failed to wrap first fd: %v", err)
	}

	t.Cleanup(func() { _ = c1.Close() })

	c2, err = socket.New(fds[1], "unix-2")
	if err != nil {
		t.Fatalf("failed to wrap second fd: %v", err)
	}

	t.Cleanup(func() { _ = c2.Close() })

	return c1, c2
}

// fillWriteBuffer writes to c until the kernel reports EAGAIN, so that a
// subsequent write must wait for the peer to drain data.
func fillWriteBuffer(t *testing.T, c *socket.Conn) {
	t.Helper()

	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("failed to get raw conn: %v", err)
	}

	b := make([]byte, 64*1024)
	err = rc.Control(func(fd uintptr) {
		for {
			_, werr := unix.Write(int(fd), b)
			switch werr {
			case nil, unix.EINTR:
				continue
			case unix.EAGAIN:
				return
			default:
				t.Errorf("unexpected error filling write buffer: %v", werr)
				return
			}
		}
	})
	if err != nil {
		t.Fatalf("failed to fill write buffer: %v", err)
	}
}

// firstCall returns a channel which is closed the first time signal is
// invoked, so tests can wait until a blocked ReadFunc or WriteFunc has made
// its initial attempt before acting on the peer.
func firstCall() (attempted <-chan struct{}, signal func()) {
	var (
		once sync.Once
		ch   = make(chan struct{})
	)

	return ch, func() { once.Do(func() { close(ch) }) }
}

// checkSyscallError verifies that err is an *os.SyscallError for op which
// wraps want.
func checkSyscallError(t *testing.T, op string, want, err error) {
	t.Helper()

	var serr *os.SyscallError
	if !errors.As(err, &serr) {
		t.Fatalf("expected *os.SyscallError, but got: %T: %v", err, err)
	}

	if diff := cmp.Diff(op, serr.Syscall); diff != "" {
		t.Fatalf("unexpected syscall name (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(want, serr.Err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("unexpected wrapped error (-want +got):\n%s", diff)
	}
}
