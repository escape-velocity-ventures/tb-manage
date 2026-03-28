//go:build windows

package scanner

import "context"

func detectPlatforms(_ context.Context, _ CommandRunner) []PlatformInfo {
	// TODO: detect Hyper-V, Docker Desktop, WSL2
	return nil
}

func listServices(_ context.Context, _ CommandRunner) []ServiceEntry {
	// TODO: implement via Get-Service / sc query
	return nil
}

func listListeningPorts(_ context.Context, _ CommandRunner) []ListeningPort {
	// TODO: implement via netstat -ano or Get-NetTCPConnection
	return nil
}
