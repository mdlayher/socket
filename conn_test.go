package socket_test

import (
	"net"
	"testing"

	"github.com/mdlayher/socket/internal/sockettest"
	"golang.org/x/net/nettest"
)

func TestConn(t *testing.T) {
	// Use our TCP net.Listener and net.Conn implementations backed by *socket.Conn
	// and run compliance tests with nettest.TestConn.
	//
	// This nettest.MakePipe function is adapted from nettest's own tests:
	// https://github.com/golang/net/blob/master/nettest/conntest_test.go
	//
	// Copyright 2016 The Go Authors. All rights reserved. Use of this source
	// code is governed by a BSD-style license that can be found in the LICENSE
	// file.
	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
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
	})
}
