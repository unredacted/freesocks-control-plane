//go:build tools

// Package agebuild pins the age release the backup sidecar runs. Nothing here
// is compiled into a program of ours: docker/backup.Dockerfile builds age's own
// commands from this module, so go.mod is the version Dependabot moves.
package agebuild

import (
	_ "filippo.io/age/cmd/age"
	_ "filippo.io/age/cmd/age-keygen"
)
