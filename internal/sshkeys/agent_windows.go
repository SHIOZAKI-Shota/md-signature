//go:build windows

package sshkeys

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// named pipe of the Windows OpenSSH agent service
const windowsAgentPipe = `\.\pipe\openssh-ssh-agent`

func dialAgent() (net.Conn, error) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if strings.HasPrefix(sock, `\.\pipe\`) || strings.HasPrefix(sock, `//./pipe/`) {
			return dialPipe(strings.ReplaceAll(sock, "/", `\`))
		}
		if c, err := dialUnix(sock); err == nil {
			return c, nil
		}
	}
	c, err := dialPipe(windowsAgentPipe)
	if err != nil {
		return nil, nil // agent not running: fall back to key files
	}
	return c, nil
}

func dialPipe(name string) (net.Conn, error) {
	timeout := 2 * time.Second
	return winio.DialPipe(name, &timeout)
}
