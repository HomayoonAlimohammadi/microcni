package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	pkgcni "github.com/HomayoonAlimohammadi/microcni/pkg/cni"
)

func ReadNetConfig(r io.Reader) (pkgcni.NetConfig, error) {
	configBytes, err := io.ReadAll(r)
	if err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to read config from stdin: %w", err)
	}

	var netConfig pkgcni.NetConfig
	if err := json.Unmarshal(configBytes, &netConfig); err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if netConfig.PodCIDR == "" {
		return pkgcni.NetConfig{}, fmt.Errorf("PodCIDR not specified in config")
	}

	baseIP, _, err := net.ParseCIDR(netConfig.PodCIDR)
	if err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to parse podcidr %q: %w", netConfig.PodCIDR, err)
	}
	if baseIP.To4() == nil {
		return pkgcni.NetConfig{}, fmt.Errorf("PodCIDR %q is not IPv4. Only IPv4 is supported", netConfig.PodCIDR)
	}

	return netConfig, nil
}
