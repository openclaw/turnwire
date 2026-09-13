package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/identity"
)

func runPeer(args []string, opts options, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError("usage: turnwire peer <add|rotate|remove>")
	}
	switch args[0] {
	case "add":
		return runPeerAdd(args[1:], opts, stdout)
	case "rotate":
		return runPeerRotate(args[1:], opts, stdout)
	case "remove":
		return runPeerRemove(args[1:], opts, stdout)
	default:
		return usageError("unknown peer command %q", args[0])
	}
}

func runPeerAdd(args []string, opts options, stdout io.Writer) error {
	if len(args) != 2 {
		return usageError("usage: turnwire peer add NAME PUBLIC_KEY")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	for _, peer := range cfg.Identity.Peers {
		if peer.Name == args[0] {
			return usageError("peer %q already exists", args[0])
		}
	}
	cfg.Identity.Peers = append(cfg.Identity.Peers, config.PeerConfig{Name: args[0], PublicKey: args[1]})
	if err := cfg.Validate(); err != nil {
		return usageError("%v", err)
	}
	if err := writeUpdatedConfig(opts, cfg); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Added peer %s\n", strconv.Quote(args[0]))
	}
	return err
}

func runPeerRotate(args []string, opts options, stdout io.Writer) error {
	if len(args) != 2 {
		return usageError("usage: turnwire peer rotate NAME ROTATION_FILE")
	}
	file, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var rotation identity.Rotation
	if err := decoder.Decode(&rotation); err != nil {
		return fmt.Errorf("decode identity rotation: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode identity rotation: multiple JSON values")
		}
		return fmt.Errorf("decode identity rotation: %w", err)
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	found := false
	for index := range cfg.Identity.Peers {
		if cfg.Identity.Peers[index].Name != args[0] {
			continue
		}
		if err := identity.VerifyRotation(rotation, args[0], cfg.Identity.Peers[index].PublicKey); err != nil {
			return err
		}
		cfg.Identity.Peers[index].PublicKey = rotation.NewPublicKey
		found = true
		break
	}
	if !found {
		return usageError("peer %q is not configured", args[0])
	}
	if err := writeUpdatedConfig(opts, cfg); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Rotated peer %s to %s\n", args[0], rotation.NewPublicKey)
	}
	return err
}

func runPeerRemove(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("peer remove", flag.ContinueOnError)
	var force bool
	flags.BoolVar(&force, "force", false, "confirm peer removal")
	rest, help, err := parseFlags(flags, args, stdout, peerHelp)
	if err != nil || help {
		return err
	}
	if len(rest) != 1 {
		return usageError("usage: turnwire peer remove --force NAME")
	}
	if !force {
		return usageError("peer remove requires --force")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	peers := cfg.Identity.Peers[:0]
	found := false
	for _, peer := range cfg.Identity.Peers {
		if peer.Name == rest[0] {
			found = true
			continue
		}
		peers = append(peers, peer)
	}
	if !found {
		return usageError("peer %q is not configured", rest[0])
	}
	cfg.Identity.Peers = peers
	if err := writeUpdatedConfig(opts, cfg); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Removed peer %s\n", rest[0])
	}
	return err
}

func writeUpdatedConfig(opts options, cfg config.Config) error {
	path := opts.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	return config.Write(path, cfg, true)
}
