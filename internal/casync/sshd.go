package casync

import (
	"log/slog"
	"os/exec"
	"runtime"
)

// restartSSHDService restarts the sshd service using systemctl.
func restartSSHDService(log *slog.Logger) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "restart", "sshd")
	case "darwin":
		// macOS uses launchctl for sshd
		cmd = exec.Command("launchctl", "kickstart", "-k", "system/com.openssh.sshd")
	default:
		log.Warn("sshd restart not supported on this platform", "os", runtime.GOOS)
		return
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Error("sshd restart failed", "error", err, "output", string(output))
	} else {
		log.Info("sshd restarted successfully")
	}
}
