package ip

import (
	"fmt"
	"net"
	"strings"
)

// ReplaceLastByte replaces the last byte of an IP address string with a given integer.
// It assumes the IP address is in the format "x.x.x.x".
// We don't check this assumption for efficienty and it's on the caller to ensure the format.
func ReplaceLastByte(ipStr string, n int) string {
	parts := strings.Split(ipStr, ".")
	parts[3] = fmt.Sprint(n)
	return strings.Join(parts, ".")
}

// GetGatewayIP calculates the gateway IP address by adding 1 to the base IP.
func GetGatewayIP(baseIP net.IP) (net.IP, error) {
	if baseIP.To4() == nil {
		return nil, fmt.Errorf("base IP is not IPv4")
	}

	gwIPStr := ReplaceLastByte(baseIP.String(), 1)

	gwIP := net.ParseIP(gwIPStr)
	if gwIP == nil {
		return nil, fmt.Errorf("failed to parse gateway IP: %s", gwIPStr)
	}

	return gwIP, nil
}
