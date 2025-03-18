package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// Commands
	CommandAdd     string = "ADD"
	CommandDel     string = "DEL"
	CommandGet     string = "GET"
	CommandVersion string = "VERSION"

	// CNI environment variables
	EnvCNICommand     string = "CNI_COMMAND"
	EnvCNIIFName      string = "CNI_IFNAME"
	EnvCNINetNS       string = "CNI_NETNS"
	EnvCNIContainerID string = "CNI_CONTAINERID"

	// Misc
	bridgeName           string = "cni0"
	cniVersion           string = "0.3.1"
	cniSupportedVersions string = "[ \"0.3.0\", \"0.3.1\", \"0.4.0\" ]"
	ipAllocFile          string = "/tmp/last_allocated_ip"
	logFile              string = "/var/log/cni.log"
)

// NetConfig represents the expected network configuration JSON.
type NetConfig struct {
	PodCIDR string `json:"podcidr"`
}

// Interface represents the output interface format.
type Interface struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	Sandbox string `json:"sandbox"`
}

// IP represents the output IP format.
type IP struct {
	Version   string `json:"version"`
	Address   string `json:"address"`
	Gateway   string `json:"gateway"`
	Interface int    `json:"interface"`
}

// CNIResult represents the JSON output for an ADD command.
type CNIResult struct {
	CNIVersion string      `json:"cniVersion"`
	Interfaces []Interface `json:"interfaces"`
	IPs        []IP        `json:"ips"`
}

func main() {
	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	configBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read config from stdin: %v", err)
	}

	// Log the environment variables and config.
	envVars := []string{EnvCNICommand, EnvCNIIFName, EnvCNINetNS, EnvCNIContainerID}
	for _, env := range envVars {
		log.Printf("%s: %s", env, os.Getenv(env))
	}
	log.Printf("STDIN: %s", string(configBytes))

	// Get the CNI command.
	cmd := os.Getenv(EnvCNICommand)
	switch cmd {
	case CommandAdd:
		if err := handleAdd(configBytes); err != nil {
			log.Fatalf("Error in ADD command: %v", err)
		}
	case CommandDel:
		if err := handleDel(); err != nil {
			log.Fatalf("Error in DEL command: %v", err)
		}
	case CommandGet:
		// No operation for GET.
	case CommandVersion:
		printVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown CNI command: %s\n", cmd)
		os.Exit(1)
	}
}

// handleAdd implements the ADD command.
func handleAdd(configBytes []byte) error {
	var netConfig NetConfig
	if err := json.Unmarshal(configBytes, &netConfig); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if netConfig.PodCIDR == "" {
		return fmt.Errorf("podcidr not specified in config")
	}

	baseIP, _, err := net.ParseCIDR(netConfig.PodCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse podcidr %q: %w", netConfig.PodCIDR, err)
	}

	gatewayIP, err := getGatewayIP(baseIP)
	if err != nil {
		return fmt.Errorf("failed to get gateway IP: %w", err)
	}

	gatewayIPStr := gatewayIP.String()

	if err := runCommand("ip", "link", "add", bridgeName, "type", "bridge"); err != nil {
		// Ignore error if bridge already exists.
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to add bridge: %w", err)
		}
	}

	if err := runCommand("ip", "link", "set", bridgeName, "up"); err != nil {
		return fmt.Errorf("failed to set bridge up: %w", err)
	}

	if err := runCommand("ip", "addr", "add", fmt.Sprintf("%s/24", gatewayIPStr), "dev", bridgeName); err != nil {
		// Ignore if the address is already assigned.
		if !strings.Contains(err.Error(), "Address already assigned") {
			return fmt.Errorf("failed to add address to bridge: %w", err)
		}
	}

	podIP, err := allocateIP(netConfig.PodCIDR)
	if err != nil {
		return fmt.Errorf("IP allocation failed: %w", err)
	}

	interim := strings.Split(podIP.String(), ".")
	devNum := interim[len(interim)-1]

	hostIfname := fmt.Sprintf("veth%s", devNum)
	podIfname := fmt.Sprintf("pod%s", devNum)

	if err := runCommand("ip", "link", "add", hostIfname, "type", "veth", "peer", "name", podIfname); err != nil {
		return fmt.Errorf("failed to add veth pair: %w", err)
	}

	if err := runCommand("ip", "link", "set", hostIfname, "up"); err != nil {
		return fmt.Errorf("failed to set %s up: %w", hostIfname, err)
	}

	contNetns := filepath.Base(os.Getenv(EnvCNINetNS))

	if err := runCommand("ip", "link", "set", hostIfname, "master", bridgeName); err != nil {
		return fmt.Errorf("failed to set %s master to %s: %w", hostIfname, bridgeName, err)
	}

	if err := runCommand("ip", "link", "set", podIfname, "netns", contNetns); err != nil {
		return fmt.Errorf("failed to set %s into netns %s: %w", podIfname, contNetns, err)
	}

	cniIfname := os.Getenv(EnvCNIIFName)
	if err := runCommand("ip", "-n", contNetns, "link", "set", podIfname, "name", cniIfname); err != nil {
		return fmt.Errorf("failed to rename interface in netns: %w", err)
	}

	if err := runCommand("ip", "-n", contNetns, "link", "set", cniIfname, "up"); err != nil {
		return fmt.Errorf("failed to set interface %s up in netns: %w", cniIfname, err)
	}

	if err := runCommand("ip", "-n", contNetns, "addr", "add", fmt.Sprintf("%s/24", podIP.String()), "dev", cniIfname); err != nil {
		return fmt.Errorf("failed to add address to interface in netns: %w", err)
	}

	if err := runCommand("ip", "-n", contNetns, "route", "add", "default", "via", gatewayIPStr); err != nil {
		return fmt.Errorf("failed to add default route in netns: %w", err)
	}

	mac, err := getInterfaceMAC(contNetns, cniIfname)
	if err != nil {
		return fmt.Errorf("failed to get MAC address: %v", err)
	}

	result := CNIResult{
		CNIVersion: cniVersion,
	}
	result.Interfaces = []Interface{
		{
			Name:    cniIfname,
			MAC:     mac,
			Sandbox: os.Getenv(EnvCNINetNS),
		},
	}
	result.IPs = []IP{
		{
			Version:   "4",
			Address:   fmt.Sprintf("%s/24", podIP.String()),
			Gateway:   gatewayIPStr,
			Interface: 0,
		},
	}

	outputBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	output := string(outputBytes)
	log.Printf("OUTPUT: %s", output)
	fmt.Fprintln(os.Stdout, output)

	return nil
}

// handleDel implements the DEL command.
func handleDel() error {
	data, err := os.ReadFile(ipAllocFile)
	if err != nil {
		log.Printf("No IP to delete: %v", err)
		return nil
	}

	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("failed to parse allocated IP number: %w", err)
	}

	hostIfname := fmt.Sprintf("veth%d", n)
	if err := runCommand("ip", "link", "del", hostIfname); err != nil {
		return fmt.Errorf("failed to delete interface %s: %w", hostIfname, err)
	}

	log.Printf("Deleted %s", hostIfname)
	return nil
}

// printVersion prints the plugin version information.
func printVersion() {
	versionJSON := `{
  "cniVersion": %s, 
  "supportedVersions": %s
}`
	fmt.Printf(versionJSON, cniVersion, cniSupportedVersions)
}

// runCommand executes a command and returns combined output or an error.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Uncomment the next line to log the commands being executed.
	// log.Printf("Executing command: %s %s", name, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %s %v failed: %w - %s", name, args, err, stderr.String())
	}
	return nil
}

// getInterfaceMAC retrieves the MAC address of an interface within a given network namespace.
func getInterfaceMAC(netns, ifname string) (string, error) {
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

// allocateIP allocates the next available IP address within the podCIDR.
// It uses a file lock on ipAllocFile to prevent race conditions.
// It returns the allocated number and the computed IP address (network + allocated number).
func allocateIP(podCIDR string) (net.IP, error) {
	baseIP, ipNet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse podCIDR: %v", err)
	}

	f, err := os.OpenFile(ipAllocFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open ip allocation file: %w", err)
	}
	defer f.Close()

	// Lock the file.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("failed to lock ip allocation file: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read allocation file: %w", err)
	}

	current := 1
	if len(data) > 0 {
		current, err = strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("failed to parse allocation number: %w", err)
		}
	}

	containerIP := ipAdd(baseIP, current+1)

	if !ipNet.Contains(containerIP) {
		return nil, fmt.Errorf("allocated IP %s is out of the podCIDR range %s", containerIP.String(), ipNet.String())
	}

	// Write the new allocation back.
	if err := f.Truncate(0); err != nil {
		return nil, fmt.Errorf("failed to truncate allocation file: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek allocation file: %w", err)
	}
	if _, err := f.WriteString(fmt.Sprintf("%d", allocatedNumber)); err != nil {
		return nil, fmt.Errorf("failed to write allocation file: %w", err)
	}

	return containerIP, nil
}

// getGatewayIP calculates the gateway IP address by adding 1 to the base IP.
func getGatewayIP(baseIP net.IP) (net.IP, error) {
	gwIP := ipAdd(baseIP, 1)
	if gwIP == nil {
		return nil, fmt.Errorf("failed to add 1 to base IP")
	}

	return gwIP, nil
}

// ipAdd adds an integer offset to an IPv4 address.
func ipAdd(ip net.IP, add int) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	// Convert IP to an integer.
	intIP := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	intIP += uint32(add)
	// Convert back to net.IP.
	return net.IPv4(byte(intIP>>24), byte(intIP>>16), byte(intIP>>8), byte(intIP))
}
