package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
)

func requireAuditCapacity(log *audit.Log) error {
	used, max, err := log.Usage()
	if err != nil {
		return err
	}
	if used >= max {
		return audit.ErrQuotaExceeded
	}
	return nil
}

func openWritableAudit(dir string, max int64) (*audit.Log, error) {
	log, err := audit.OpenWithQuota(dir, max)
	if err != nil {
		return nil, err
	}
	if err := requireAuditCapacity(log); err != nil {
		return nil, errors.Join(err, log.Close())
	}
	return log, nil
}
func writeJSONOutput(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
func resolveAuditDir(cfg config.Config, dataDir string) (string, error) {
	if dataDir != "" {
		absolute, err := filepath.Abs(dataDir)
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Clean(absolute), "audit"), nil
	}
	if cfg.AuditDir != "" {
		return cfg.AuditDir, nil
	}
	base := config.DefaultDataDir()
	if base == "" {
		return "", errors.New("cannot determine default data directory")
	}
	return filepath.Join(base, "audit"), nil
}

func runVersion(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, versionHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if asJSON {
		return writeJSONOutput(stdout, buildinfo.Current())
	}
	return writeOutput(stdout, []byte(versionLine()))
}
