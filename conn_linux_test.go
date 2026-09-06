//go:build linux

package socket_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/socket"
	"github.com/mdlayher/socket/internal/sockettest"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func TestLinuxConnBuffers(t *testing.T) {
	t.Parallel()

	// This test isn't necessarily Linux-specific but it's easiest to verify on
	// Linux because we can rely on the kernel's documented buffer size
	// manipulation behavior.
	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	const (
		set = 8192

		// Per socket(7):
		//
		// "The kernel doubles this value (to allow space for
		// book‐keeping overhead) when it is set using setsockopt(2),
		// and this doubled value is returned by getsockopt(2).""
		want = set * 2
	)

	if err := c.SetReadBuffer(set); err != nil {
		t.Fatalf("failed to set read buffer size: %v", err)
	}

	if err := c.SetWriteBuffer(set); err != nil {
		t.Fatalf("failed to set write buffer size: %v", err)
	}

	// Now that we've set the buffers, we can check the size by asking the
	// kernel using SyscallConn and getsockopt.

	rcv, err := c.ReadBuffer()
	if err != nil {
		t.Fatalf("failed to get read buffer size: %v", err)
	}

	snd, err := c.WriteBuffer()
	if err != nil {
		t.Fatalf("failed to get write buffer size: %v", err)
	}

	if diff := cmp.Diff(want, rcv); diff != "" {
		t.Fatalf("unexpected read buffer size (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want, snd); diff != "" {
		t.Fatalf("unexpected write buffer size (-want +got):\n%s", diff)
	}
}

func TestLinuxNetworkNamespaces(t *testing.T) {
	t.Parallel()

	l, err := sockettest.Listen(0, nil)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer l.Close()

	addrC := make(chan net.Addr, 1)

	var eg errgroup.Group
	eg.Go(func() error {
		// We are poisoning this thread by creating a new anonymous network
		// namespace. Do not unlock the OS thread so that the runtime will kill
		// this thread when the goroutine exits.
		runtime.LockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			// Explicit wrap to check for permission denied.
			return fmt.Errorf("failed to unshare network namespace: %w", err)
		}

		ns, err := socket.ThreadNetNS()
		if err != nil {
			return fmt.Errorf("failed to get listener thread's network namespace: %v", err)
		}

		// This OS thread has been moved to a different network namespace and
		// thus we should also be able to start a listener on the same port.
		l, err := sockettest.Listen(
			l.Addr().(*net.TCPAddr).Port,
			&socket.Config{NetNS: ns.FD()},
		)
		if err != nil {
			return fmt.Errorf("failed to create listener in network namespace: %v", err)
		}
		defer l.Close()

		addrC <- l.Addr()
		return nil
	})

	if err := eg.Wait(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping, permission denied: %v", err)
		}

		t.Fatalf("failed to run listener thread: %v", err)
	}

	select {
	case addr := <-addrC:
		if diff := cmp.Diff(l.Addr(), addr); diff != "" {
			t.Fatalf("unexpected network address (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("listener thread did not return its local address")
	}
}

func TestLinuxDialVsockNoListener(t *testing.T) {
	t.Parallel()

	// See https://github.com/mdlayher/vsock/issues/47 and
	// https://github.com/lxc/lxd/pull/9894 for context on this test.
	c, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "vsock", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	// Given a (hopefully) non-existent listener on localhost, expect
	// ECONNRESET.
	_, err = c.Connect(context.Background(), &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_LOCAL,
		Port: math.MaxUint32,
	})
	if err == nil {
		// See https://github.com/mdlayher/socket/issues/4.
		t.Skipf("skipping, expected error but vsock successfully connected to local service")
	}

	want := os.NewSyscallError("connect", unix.ECONNRESET)
	if diff := cmp.Diff(want, err); diff != "" {
		t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
	}
}

func TestLinuxOpenPIDFD(t *testing.T) {
	// Verify we can use regular files with socket by properly handling
	// ENOTSOCK, as is the case with pidfds.
	fd, err := unix.PidfdOpen(1, unix.PIDFD_NONBLOCK)
	if err != nil {
		t.Fatalf("failed to open pidfd for init: %v", err)
	}

	c, err := socket.New(fd, "pidfd")
	if err != nil {
		t.Fatalf("failed to open Conn for pidfd: %v", err)
	}
	_ = c.Close()
}

func TestLinuxBindToDevice(t *testing.T) {
	t.Parallel()

	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	// Assumes the loopback interface is always the first device on Linux
	// machines.
	const (
		name  = "lo"
		index = 1
	)

	if err := c.SetsockoptString(unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); err != nil {
		t.Fatalf("failed to bind to device: %v", err)
	}

	gotName, err := c.GetsockoptString(unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil {
		t.Fatalf("failed to get bound interface name: %v", err)
	}
	if diff := cmp.Diff(name, gotName); diff != "" {
		t.Fatalf("unexpected interface name (-want +got):\n%s", diff)
	}

	gotIndex, err := c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	if err != nil {
		t.Fatalf("failed to get bound interface index: %v", err)
	}
	if diff := cmp.Diff(index, gotIndex); diff != "" {
		t.Fatalf("unexpected interface index (-want +got):\n%s", diff)
	}
}

func TestLinuxConnSockoptBytesRoundTrip(t *testing.T) {
	t.Parallel()

	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	// Set SO_RCVBUF as a raw 4-byte native-endian integer, then read it back
	// both as raw bytes and as an integer and verify they agree. Per
	// socket(7) the kernel doubles the value that was set.
	const set = 8192
	in := binary.NativeEndian.AppendUint32(nil, set)

	if err := c.SetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, in); err != nil {
		t.Fatalf("failed to set SO_RCVBUF bytes: %v", err)
	}

	want, err := c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		t.Fatalf("failed to get SO_RCVBUF int: %v", err)
	}
	if diff := cmp.Diff(set*2, want); diff != "" {
		t.Fatalf("unexpected SO_RCVBUF int (-want +got):\n%s", diff)
	}

	out := make([]byte, 4)
	n, err := c.GetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, out)
	if err != nil {
		t.Fatalf("failed to get SO_RCVBUF bytes: %v", err)
	}
	if diff := cmp.Diff(4, n); diff != "" {
		t.Fatalf("unexpected SO_RCVBUF optlen (-want +got):\n%s", diff)
	}

	got := int(binary.NativeEndian.Uint32(out))
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected SO_RCVBUF bytes value (-want +got):\n%s", diff)
	}
}

func TestLinuxConnGetsockoptBytesShortOptlen(t *testing.T) {
	t.Parallel()

	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	want, err := c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		t.Fatalf("failed to get SO_SNDBUF int: %v", err)
	}

	// Pass a buffer larger than the option and fill the trailing bytes with a
	// sentinel value: the kernel must report the true optlen and leave the
	// bytes beyond it untouched.
	out := bytes.Repeat([]byte{0xff}, 16)
	n, err := c.GetsockoptBytes(unix.SOL_SOCKET, unix.SO_SNDBUF, out)
	if err != nil {
		t.Fatalf("failed to get SO_SNDBUF bytes: %v", err)
	}
	if diff := cmp.Diff(4, n); diff != "" {
		t.Fatalf("unexpected SO_SNDBUF optlen (-want +got):\n%s", diff)
	}

	got := int(binary.NativeEndian.Uint32(out[:n]))
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected SO_SNDBUF bytes value (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(bytes.Repeat([]byte{0xff}, 12), out[n:]); diff != "" {
		t.Fatalf("unexpected trailing bytes (-want +got):\n%s", diff)
	}

	// An unbound socket reports SO_BINDTODEVICE with optlen 0 and does not
	// touch the buffer.
	name := bytes.Repeat([]byte{0xff}, unix.IFNAMSIZ)
	n, err = c.GetsockoptBytes(unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
	if err != nil {
		t.Fatalf("failed to get SO_BINDTODEVICE bytes: %v", err)
	}
	if diff := cmp.Diff(0, n); diff != "" {
		t.Fatalf("unexpected SO_BINDTODEVICE optlen (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(bytes.Repeat([]byte{0xff}, unix.IFNAMSIZ), name); diff != "" {
		t.Fatalf("unexpected SO_BINDTODEVICE bytes (-want +got):\n%s", diff)
	}
}

func TestLinuxConnSockoptBytesEmpty(t *testing.T) {
	t.Parallel()

	c, err := socket.Socket(unix.AF_INET, unix.SOCK_STREAM, 0, "tcpv4", nil)
	if err != nil {
		t.Fatalf("failed to open socket: %v", err)
	}
	defer c.Close()

	for _, b := range [][]byte{nil, {}} {
		// Empty buffers must pass a nil pointer with optlen 0 rather than
		// panicking. The kernel rejects an integer option that is too short.
		err := c.SetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, b)
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("expected EINVAL from empty setsockopt, but got: %v", err)
		}

		// The kernel clamps optlen to the buffer size, so getsockopt with an
		// empty buffer succeeds and reports optlen 0.
		n, err := c.GetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, b)
		if err != nil {
			t.Fatalf("failed to get SO_RCVBUF with empty buffer: %v", err)
		}
		if diff := cmp.Diff(0, n); diff != "" {
			t.Fatalf("unexpected empty getsockopt optlen (-want +got):\n%s", diff)
		}
	}

	// Closed connections must report EBADF.
	if err := c.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if err := c.SetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, []byte{0, 0, 0, 0}); !errors.Is(err, unix.EBADF) {
		t.Fatalf("expected EBADF from closed setsockopt, but got: %v", err)
	}
	if _, err := c.GetsockoptBytes(unix.SOL_SOCKET, unix.SO_RCVBUF, make([]byte, 4)); !errors.Is(err, unix.EBADF) {
		t.Fatalf("expected EBADF from closed getsockopt, but got: %v", err)
	}
}
