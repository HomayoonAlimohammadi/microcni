package ipam

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	pkgipam "github.com/HomayoonAlimohammadi/microcni/pkg/ipam"
	"github.com/HomayoonAlimohammadi/microcni/pkg/net/ip"
)

// FileIPAM implements the IPAM interface using a file as the backend.
type FileIPAM struct {
	lockFile      string
	lockFilePerm  os.FileMode
	allocFile     string
	allocFilePerm os.FileMode
	podCIDR       string
}

var _ pkgipam.IPAM = &FileIPAM{}

// NewFileIPAM creates a new inFileIPAM instance with the specified lock file and allocation file.
func NewFileIPAM(lockFile, allocFile string, podCIDR string) *FileIPAM {
	return &FileIPAM{
		lockFile:      lockFile,
		lockFilePerm:  0644,
		allocFile:     allocFile,
		allocFilePerm: 0644,
		podCIDR:       podCIDR,
	}
}

// Lock acquires a lock by creating a lock file.
// If the lock exists it keeps retrying until it can create the file.
func (i *FileIPAM) Lock() error {
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
func (i *FileIPAM) Unlock() error {
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
func (i *FileIPAM) AllocateIP(containerID string) (net.IP, error) {
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
		candidIP := ip.ReplaceLastByte(baseIPStr, last)
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
func (i *FileIPAM) Lookup(containerID string) (net.IP, bool, error) {
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
func (i *FileIPAM) Free(ip net.IP) (string, bool, error) {
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
