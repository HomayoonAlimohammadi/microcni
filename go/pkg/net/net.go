package net

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const (
	hostPeerNamePrefix      = "veth"
	containerPeerNamePrefix = "pod"
)

// GetInterfaceMAC retrieves the MAC address of an interface within a given network namespace.
func GetInterfaceMAC(netns, ifname string) (string, error) {
	cmd := exec.Command("ip", "-n", netns, "link", "show", ifname)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to show interface: %v", err)
	}

	// Find the line containing "ether" and extract the MAC.
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "link/ether") {
			if parts := strings.Fields(line); len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("MAC address not found")
}

// HostPeerName generates the host device name based on the device number.
func HostPeerName(devNum string) string {
	return fmt.Sprintf("%s%s", hostPeerNamePrefix, devNum)
}

// ContainerPeerName generates the container device name based on the device number.
func ContainerPeerName(devNum string) string {
	return fmt.Sprintf("%s%s", containerPeerNamePrefix, devNum)
}
