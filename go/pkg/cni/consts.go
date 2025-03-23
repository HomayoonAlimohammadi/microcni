package cni

const (
	// Commands
	CommandAdd     string = "ADD"
	CommandDel     string = "DEL"
	CommandGet     string = "GET"
	CommandVersion string = "VERSION"

	// CNI environment variables
	EnvCommand     string = "CNI_COMMAND"
	EnvIFName      string = "CNI_IFNAME"
	EnvNetNS       string = "CNI_NETNS"
	EnvContainerID string = "CNI_CONTAINERID"
)
