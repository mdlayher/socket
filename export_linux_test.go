//go:build linux
// +build linux

package socket

// A NetNS is an exported wrapper for netNS for tests.
type NetNS struct{ *netNS }

// ThreadNetNS is an exported wrapper for threadNetNS for tests.
func ThreadNetNS() (*NetNS, error) {
	ns, err := threadNetNS()
	if err != nil {
		return nil, err
	}

	return &NetNS{ns}, nil
}
