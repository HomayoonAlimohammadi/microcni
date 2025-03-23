package main

import (
	"fmt"
	"log"
	"os"

	internalcni "github.com/HomayoonAlimohammadi/microcni/internal/cni"
	"github.com/HomayoonAlimohammadi/microcni/internal/config"
	internalipam "github.com/HomayoonAlimohammadi/microcni/internal/ipam"
	pkgcni "github.com/HomayoonAlimohammadi/microcni/pkg/cni"
)

const (
	ipamAllocFile string = "/tmp/ipam.json"
	ipamLockFile  string = "/tmp/ipam.lock"
	logFile       string = "/var/log/cni.log"
)

func main() {
	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	netConfig, err := config.ReadNetConfig(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read net config: %v\n", err)
	}

	// Log the environment variables and config.
	envVars := []string{pkgcni.EnvCommand, pkgcni.EnvIFName, pkgcni.EnvNetNS, pkgcni.EnvContainerID}
	for _, env := range envVars {
		log.Printf("%s: %s", env, os.Getenv(env))
	}
	log.Printf("STDIN: %+v\n", netConfig)

	ipam := internalipam.NewFileIPAM(ipamLockFile, ipamAllocFile, netConfig.PodCIDR)
	plugin := internalcni.NewPlugin(netConfig, ipam)

	cmd := os.Getenv(pkgcni.EnvCommand)
	switch cmd {
	case pkgcni.CommandAdd:
		if err := plugin.HandleAdd(); err != nil {
			log.Fatalf("failed to handle add: %v\n", err)
		}
	case pkgcni.CommandDel:
		if err := plugin.HandleDel(); err != nil {
			log.Fatalf("failed to handle del: %v\n", err)
		}
	case pkgcni.CommandGet:
		if err := plugin.HandleGet(); err != nil {
			log.Fatalf("failed to handle get: %v\n", err)
		}
	case pkgcni.CommandVersion:
		if err := plugin.HandleVersion(); err != nil {
			log.Fatalf("failed to handle version: %v\n", err)
		}
	default:
		log.Fatalf("unknown CNI command: %s\n", cmd)
	}
}
