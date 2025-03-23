package cni

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

// Result represents the JSON output for an ADD command.
type Result struct {
	CNIVersion string      `json:"cniVersion"`
	Interfaces []Interface `json:"interfaces"`
	IPs        []IP        `json:"ips"`
}
