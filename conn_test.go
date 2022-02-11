package socket_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/socket/internal/sockettest"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

func TestConn(t *testing.T) {
	nettest.TestConn(t, makePipe)

	// Our own extensions to TestConn.
	t.Run("CloseReadWrite", func(t *testing.T) { timeoutWrapper(t, makePipe, testCloseReadWrite) })
}

func TestDialTCPNoListener(t *testing.T) {
	// See https://github.com/mdlayher/vsock/issues/47 and
	// https://github.com/lxc/lxd/pull/9894 for context on this test.
	//
	//
	// Given a (hopefully) non-existent listener on localhost, expect
	// ECONNREFUSED.
	_, err := sockettest.Dial(&net.TCPAddr{
		IP:   net.IPv6loopback,
		Port: math.MaxUint16,
	}, nil)

	want := os.NewSyscallError("connect", unix.ECONNREFUSED)
	if diff := cmp.Diff(want, err); diff != "" {
		t.Fatalf("unexpected connect error (-want +got):\n%s", diff)
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
func makePipe() (c1, c2 net.Conn, stop func(), err error) {
	ln, err := sockettest.Listen(0, nil)
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
	c1, err1 = sockettest.Dial(ln.Addr(), nil)
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
		if nerr, ok := err.(net.Error); !ok || nerr.Temporary() {
			t.Errorf("unexpected final cc1.Write error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()

		// Reading succeeds at first but should result in an EOF error after
		// closing the read side of the net.Conn.
		if err := chunkedCopy(ioutil.Discard, cc2); err != nil {
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
