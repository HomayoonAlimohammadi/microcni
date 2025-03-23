package ipam

import "net"

// IPAM interface defines the methods for IP address management.
type IPAM interface {
	AllocateIP(containerID string) (net.IP, error)
	Lookup(containerID string) (net.IP, bool, error)
	Free(ip net.IP) (string, bool, error)
}
