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
	"time"
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
	ipamAllocFile string = "/tmp/ipam.json"
	ipamLockFile  string = "/tmp/ipam.lock"
	logFile       string = "/var/log/cni.log"
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

// IPAM interface defines the methods for IP address management.
type IPAM interface {
	AllocateIP(containerID string) (net.IP, error)
	Lookup(containerID string) (net.IP, bool, error)
	Free(ip net.IP) (string, bool, error)
}

type inFileIPAM struct {
	lockFile      string
	lockFilePerm  os.FileMode
	allocFile     string
	allocFilePerm os.FileMode
	podCIDR       string
}

// NewInFileIPAM creates a new inFileIPAM instance with the specified lock file and allocation file.
func NewInFileIPAM(lockFile, allocFile string, podCIDR string) *inFileIPAM {
	return &inFileIPAM{
		lockFile:      lockFile,
		lockFilePerm:  0644,
		allocFile:     allocFile,
		allocFilePerm: 0644,
		podCIDR:       podCIDR,
	}
}

// Lock acquires a lock by creating a lock file.
// If the lock exists it keeps retrying until it can create the file.
func (i *inFileIPAM) Lock() error {
	if i.lockFile == "" {
		return fmt.Errorf("lockFile must be set")
	}

	for {
		// O_EXCL with O_CREATE ensures the call fails if the file already exists
		f, err := os.OpenFile(i.lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, i.lockFilePerm)
		if err == nil {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
			return nil
		}

		if !os.IsExist(err) {
			return fmt.Errorf("failed to create lock file: %w", err)
		}

		// File exists, which means lock is held by someone else
		// Wait a bit before retrying
		time.Sleep(10 * time.Millisecond)
	}
}

// Unlock releases the lock by removing the lock file.
// If the lock file doesn't exist, it returns an error.
// If the lock file is held by another process, it returns an error.
func (i *inFileIPAM) Unlock() error {
	if i.lockFile == "" {
		return fmt.Errorf("lockFile must be set")
	}

	// check if the pid in the lock file is ours
	b, err := os.ReadFile(i.lockFile)
	if err != nil {
		return fmt.Errorf("failed to read lock file: %w", err)
	}

	pidStr := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("failed to parse pid from lock file: %w", err)
	}

	if pid != os.Getpid() {
		return fmt.Errorf("failed to unlock. lock file is held by another process (pid: %d)", pid)
	}

	err = os.Remove(i.lockFile)
	if err != nil {
		return fmt.Errorf("failed to remove lock file: %w", err)
	}

	return nil
}

// AllocateIP allocates an IP address for a container.
func (i *inFileIPAM) AllocateIP(containerID string) (net.IP, error) {
	i.Lock()
	defer i.Unlock()

	baseIP, ipNet, err := net.ParseCIDR(i.podCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse podCIDR: %v", err)
	}

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read allocation file: %w", err)
		}
	}

	contIDToIP := make(map[string]string)

	if len(b) > 0 {
		if err := json.Unmarshal(b, &contIDToIP); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allocation file: %w", err)
		}
	}

	allocatedIPs := make(map[string]struct{}, len(contIDToIP))
	for _, ip := range contIDToIP {
		allocatedIPs[ip] = struct{}{}
	}

	baseIPStr := baseIP.String()
	for last := 2; last < 255; last++ {
		candidIP := replaceLastByte(baseIPStr, last)
		if _, exists := allocatedIPs[candidIP]; !exists {
			// Found an available IP
			contIDToIP[containerID] = candidIP
			break
		}
	}

	ipStr := contIDToIP[containerID]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse allocated IP: %w", err)
	}

	if !ipNet.Contains(ip) {
		// shouldn't happen?
		return nil, fmt.Errorf("allocated IP %s is out of the podCIDR range %s", ipStr, ipNet.String())
	}

	ipMapBytes, err := json.MarshalIndent(contIDToIP, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal allocation map: %w", err)
	}

	// Write the new allocation back.
	// marshal the map to JSON and write to file
	if err := os.WriteFile(i.allocFile, ipMapBytes, i.allocFilePerm); err != nil {
		return nil, fmt.Errorf("failed to write allocation file: %w", err)
	}

	log.Printf("Allocated IP %s for container %s", ip.String(), containerID)

	return ip, nil
}

// Lookup checks if an IP address is allocated to a container.
// It returns the IP address and a boolean indicating if it was found, and an error in any.
func (i *inFileIPAM) Lookup(containerID string) (net.IP, bool, error) {
	i.Lock()
	defer i.Unlock()

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read allocation file: %w", err)
	}

	contIDToIP := make(map[string]string)
	if err := json.Unmarshal(b, &contIDToIP); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal allocation file: %w", err)
	}

	ipStr, exists := contIDToIP[containerID]
	if !exists {
		return nil, false, nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, false, fmt.Errorf("failed to parse allocated IP: %w", err)
	}

	return ip, true, nil
}

// Free frees the allocated IP address for a container.
// It returns the container ID associated with the IP address if there is any.
func (i *inFileIPAM) Free(ip net.IP) (string, bool, error) {
	i.Lock()
	defer i.Unlock()

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to read allocation file: %w", err)
	}

	contIDToIP := make(map[string]string)
	if err := json.Unmarshal(b, &contIDToIP); err != nil {
		return "", false, fmt.Errorf("failed to unmarshal allocation file: %w", err)
	}

	// Find the container ID associated with the IP address.
	var containerID string
	for id, ipStr := range contIDToIP {
		if ipStr == ip.String() {
			containerID = id
			break
		}
	}

	if containerID == "" {
		return "", false, nil
	}

	delete(contIDToIP, containerID)

	ipMapBytes, err := json.MarshalIndent(contIDToIP, "", "  ")
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal allocation map: %w", err)
	}

	// Write the updated allocation back.
	if err := os.WriteFile(i.allocFile, ipMapBytes, i.allocFilePerm); err != nil {
		return "", false, fmt.Errorf("failed to write allocation file: %w", err)
	}

	return containerID, true, nil
}

type cniPlugin struct {
	cmd         string
	ifName      string
	netNS       string
	containerID string

	bridgeName           string
	cniVersion           string
	cniSupportedVersions string

	config NetConfig
	ipam   IPAM
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

	var netConfig NetConfig
	if err := json.Unmarshal(configBytes, &netConfig); err != nil {
		log.Fatalf("failed to parse config JSON: %v", err)
	}

	if netConfig.PodCIDR == "" {
		log.Fatalf("PodCIDR not specified in config")
	}

	baseIP, _, err := net.ParseCIDR(netConfig.PodCIDR)
	if err != nil {
		log.Fatalf("Failed to parse podcidr %q: %v", netConfig.PodCIDR, err)
	}
	if baseIP.To4() == nil {
		log.Fatalf("PodCIDR %q is not IPv4. Only IPv4 is supported.", netConfig.PodCIDR)
	}

	ipam := NewInFileIPAM(ipamLockFile, ipamAllocFile, netConfig.PodCIDR)
	plugin := &cniPlugin{
		cmd:                  os.Getenv(EnvCNICommand),
		ifName:               os.Getenv(EnvCNIIFName),
		netNS:                os.Getenv(EnvCNINetNS),
		containerID:          os.Getenv(EnvCNIContainerID),
		bridgeName:           "cni0",
		cniVersion:           "0.3.1",
		cniSupportedVersions: "[ \"0.3.0\", \"0.3.1\", \"0.4.0\" ]",
		config:               netConfig,
		ipam:                 ipam,
	}

	// Log the environment variables and config.
	envVars := []string{EnvCNICommand, EnvCNIIFName, EnvCNINetNS, EnvCNIContainerID}
	for _, env := range envVars {
		log.Printf("%s: %s", env, os.Getenv(env))
	}
	log.Printf("STDIN: %s", string(configBytes))

	if err := plugin.run(); err != nil {
		log.Fatalf("CNI plugin failed: %v", err)
	}
}

// run executes the appropriate command based on the CNI_COMMAND environment variable.
func (c *cniPlugin) run() error {
	switch c.cmd {
	case CommandAdd:
		if err := c.handleAdd(); err != nil {
			return fmt.Errorf("failed to handle add: %w", err)
		}
	case CommandDel:
		if err := c.handleDel(); err != nil {
			return fmt.Errorf("failed to handle del: %w", err)
		}
	case CommandGet:
		if err := c.handleGet(); err != nil {
			return fmt.Errorf("failed to handle get: %w", err)
		}
	case CommandVersion:
		if err := c.handleVersion(); err != nil {
			return fmt.Errorf("failed to handle version: %w", err)
		}
	default:
		return fmt.Errorf("unknown CNI command: %s", c.cmd)
	}

	return nil
}

// handleAdd implements the ADD command.
func (c *cniPlugin) handleAdd() error {
	baseIP, _, err := net.ParseCIDR(c.config.PodCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse podcidr %q: %w", c.config.PodCIDR, err)
	}

	gatewayIP, err := getGatewayIP(baseIP)
	if err != nil {
		return fmt.Errorf("failed to get gateway IP: %w", err)
	}

	gatewayIPStr := gatewayIP.String()

	if err := runCommand("ip", "link", "add", c.bridgeName, "type", "bridge"); err != nil {
		// Ignore error if bridge already exists.
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to add bridge: %w", err)
		}
	}

	if err := runCommand("ip", "link", "set", c.bridgeName, "up"); err != nil {
		return fmt.Errorf("failed to set bridge up: %w", err)
	}

	if err := runCommand("ip", "addr", "add", fmt.Sprintf("%s/24", gatewayIPStr), "dev", c.bridgeName); err != nil {
		// Ignore if the address is already assigned.
		if !strings.Contains(err.Error(), "Address already assigned") {
			return fmt.Errorf("failed to add address to bridge: %w", err)
		}
	}

	podIP, err := c.ipam.AllocateIP(c.containerID)
	if err != nil {
		return fmt.Errorf("IP allocation failed: %w", err)
	}

	interim := strings.Split(podIP.String(), ".")
	devNum := interim[len(interim)-1]

	hostIfname := c.getHostDevice(devNum)
	podIfname := c.getContainerDevice(devNum)

	if err := runCommand("ip", "link", "add", hostIfname, "type", "veth", "peer", "name", podIfname); err != nil {
		return fmt.Errorf("failed to add veth pair: %w", err)
	}

	if err := runCommand("ip", "link", "set", hostIfname, "up"); err != nil {
		return fmt.Errorf("failed to set %s up: %w", hostIfname, err)
	}

	contNetns := filepath.Base(c.netNS)

	if err := runCommand("ip", "link", "set", hostIfname, "master", c.bridgeName); err != nil {
		return fmt.Errorf("failed to set %s master to %s: %w", hostIfname, c.bridgeName, err)
	}

	if err := runCommand("ip", "link", "set", podIfname, "netns", contNetns); err != nil {
		return fmt.Errorf("failed to set %s into netns %s: %w", podIfname, contNetns, err)
	}

	if err := runCommand("ip", "-n", contNetns, "link", "set", podIfname, "name", c.ifName); err != nil {
		return fmt.Errorf("failed to rename interface in netns: %w", err)
	}

	if err := runCommand("ip", "-n", contNetns, "link", "set", c.ifName, "up"); err != nil {
		return fmt.Errorf("failed to set interface %s up in netns: %w", c.ifName, err)
	}

	if err := runCommand("ip", "-n", contNetns, "addr", "add", fmt.Sprintf("%s/24", podIP.String()), "dev", c.ifName); err != nil {
		return fmt.Errorf("failed to add address to interface in netns: %w", err)
	}

	if err := runCommand("ip", "-n", contNetns, "route", "add", "default", "via", gatewayIPStr); err != nil {
		return fmt.Errorf("failed to add default route in netns: %w", err)
	}

	mac, err := getInterfaceMAC(contNetns, c.ifName)
	if err != nil {
		return fmt.Errorf("failed to get MAC address: %v", err)
	}

	result := CNIResult{
		CNIVersion: c.cniVersion,
	}
	result.Interfaces = []Interface{
		{
			Name:    c.ifName,
			MAC:     mac,
			Sandbox: c.netNS,
		},
	}
	result.IPs = []IP{
		{
			// NOTE(Hue): Only IPv4 is supported for now.
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
func (c *cniPlugin) handleDel() error {
	ip, found, err := c.ipam.Lookup(c.containerID)
	if err != nil {
		return fmt.Errorf("failed to lookup IP: %w", err)
	}

	if found {
		log.Printf("Found IP %s for container %s", ip.String(), c.containerID)
	} else {
		log.Printf("No IP found for container %s", c.containerID)
		return nil
	}

	if _, found, err = c.ipam.Free(ip); err != nil {
		return fmt.Errorf("failed to free IP: %w", err)
	}

	if found {
		log.Printf("Freed IP %s", ip.String())
	} else {
		log.Printf("IP %s not found in allocation file", ip.String())
	}

	interm := strings.Split(ip.String(), ".")
	devNum := interm[len(interm)-1]

	hostIfname := c.getHostDevice(devNum)
	if err := runCommand("ip", "link", "del", hostIfname); err != nil {
		if strings.Contains(err.Error(), "Cannot find device") {
			log.Printf("Interface %s not found, ignoring error", hostIfname)
		} else {
			return fmt.Errorf("failed to delete interface %s: %w", hostIfname, err)
		}
	} else {
		log.Printf("Deleted %s", hostIfname)
	}

	return nil
}

// getHostDevice generates the host device name based on the device number.
func (c *cniPlugin) getHostDevice(devNum string) string {
	return fmt.Sprintf("veth%s", devNum)
}

// getContainerDevice generates the container device name based on the device number.
func (c *cniPlugin) getContainerDevice(devNum string) string {
	return fmt.Sprintf("pod%s", devNum)
}

// handleGet implements the GET command.
func (c *cniPlugin) handleGet() error {
	// Implement the GET command if needed.
	// Currently, it just returns nil.
	return nil
}

// handleVersion implements the VERSION command.
func (c *cniPlugin) handleVersion() error {
	versionJSON := `{
  "cniVersion": %s, 
  "supportedVersions": %s
}`
	fmt.Printf(versionJSON, c.cniVersion, c.cniSupportedVersions)
	return nil
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

// getGatewayIP calculates the gateway IP address by adding 1 to the base IP.
func getGatewayIP(baseIP net.IP) (net.IP, error) {
	if baseIP.To4() == nil {
		return nil, fmt.Errorf("base IP is not IPv4")
	}

	gwIPStr := replaceLastByte(baseIP.String(), 1)

	gwIP := net.ParseIP(gwIPStr)
	if gwIP == nil {
		return nil, fmt.Errorf("failed to parse gateway IP: %s", gwIPStr)
	}

	return gwIP, nil
}

// replaceLastByte replaces the last byte of an IP address string with a given integer.
// It assumes the IP address is in the format "x.x.x.x".
func replaceLastByte(ipStr string, n int) string {
	parts := strings.Split(ipStr, ".")
	parts[3] = fmt.Sprint(n)
	return strings.Join(parts, ".")
}
