//go:build !windows

package sshkeys

import (
	"net"
	"os"
)

func dialAgent() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	c, err := dialUnix(sock)
	if err != nil {
		return nil, nil // stale socket: fall back to key files
	}
	return c, nil
}
