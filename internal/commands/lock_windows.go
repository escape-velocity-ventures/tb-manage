//go:build windows

package commands

import (
	"context"
	"log/slog"
)

func platformLock(_ context.Context, message string) (*LockResult, error) {
	slog.Info("lock: not yet implemented on windows", "message", message)
	return &LockResult{
		UsersDisabled:  0,
		SessionsKilled: 0,
		NologinWritten: false,
		DisabledUsers:  nil,
	}, nil
}

func platformUnlock(_ context.Context) (*UnlockResult, error) {
	slog.Info("unlock: not yet implemented on windows")
	return &UnlockResult{
		UsersEnabled:   0,
		NologinRemoved: false,
		EnabledUsers:   nil,
	}, nil
}
