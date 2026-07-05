// Package attestation measures the executable and security configuration used
// by one Turnwire process.
package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
)

// Record contains non-secret deployment evidence. Digest is stable for the
// same binary and configuration and is safe to place in audit metadata.
type Record struct {
	DeploymentID     string `json:"deployment_id"`
	Identity         string `json:"identity"`
	PublicKey        string `json:"public_key"`
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Modified         *bool  `json:"modified,omitempty"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ConfigSHA256     string `json:"config_sha256"`
	PolicySHA256     string `json:"policy_sha256"`
	PeerSetSHA256    string `json:"peer_set_sha256"`
	Digest           string `json:"digest"`
}

type peer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// Measure hashes the running executable, complete validated config, policy,
// pinned peer set, identity, and build metadata.
func Measure(cfg config.Config, publicKey string) (Record, error) {
	executable, err := os.Executable()
	if err != nil {
		return Record{}, fmt.Errorf("locate executable: %w", err)
	}
	file, err := os.Open(executable)
	if err != nil {
		return Record{}, fmt.Errorf("open executable: %w", err)
	}
	executableHash := sha256.New()
	_, copyErr := io.Copy(executableHash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return Record{}, fmt.Errorf("hash executable: %w", errors.Join(copyErr, closeErr))
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return Record{}, fmt.Errorf("encode config attestation: %w", err)
	}
	peers := make([]peer, 0, len(cfg.Identity.Peers))
	for _, configured := range cfg.Identity.Peers {
		peers = append(peers, peer{Name: configured.Name, PublicKey: configured.PublicKey})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	peerJSON, err := json.Marshal(peers)
	if err != nil {
		return Record{}, err
	}
	info := buildinfo.Current()
	record := Record{
		DeploymentID: cfg.Deployment.ID, Identity: cfg.Identity.Name, PublicKey: publicKey,
		Version: info.Version, Commit: info.Commit, Modified: info.Modified,
		ExecutableSHA256: hex.EncodeToString(executableHash.Sum(nil)),
		ConfigSHA256:     hash(configJSON), PolicySHA256: hash([]byte(cfg.Guard.Policy)),
		PeerSetSHA256: hash(peerJSON),
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	record.Digest = hash(canonical)
	return record, nil
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
