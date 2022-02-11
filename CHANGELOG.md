# CHANGELOG

## v0.1.2

- [Bug Fix]: `socket.Conn.Connect` now properly checks the `SO_ERROR` socket
  option value after calling `connect(2)` to verify whether or not a connection
  could successfully be established. This means that `Connect` should now report
  an error for an `AF_INET` TCP connection refused or `AF_VSOCK` connection
  reset by peer.
- [New API]: add `socket.Conn.Getpeername` for use in `Connect`, but also for
  use by external callers.

## v0.1.1

- [New API]: `socket.Conn` now has `CloseRead`, `CloseWrite`, and `Shutdown`
  methods.
- [Improvement]: internal rework to more robustly handle various errors.

## v0.1.0

- Initial unstable release. Most functionality has been developed and ported
from package [`netlink`](https://github.com/mdlayher/netlink).
