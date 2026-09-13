package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
)

const probeText = "Routine scheduling note: meeting moved to 10:30 tomorrow."

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

func runDoctor(ctx context.Context, args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var probe, asJSON bool
	flags.BoolVar(&probe, "probe", false, "probe the configured guard")
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, doctorHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	report := doctorReport{OK: true}
	add := func(name string, err error, ok string) {
		if err != nil {
			report.OK = false
			report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "fail", Message: err.Error()})
		} else {
			report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "ok", Message: ok})
		}
	}
	cfg, loadErr := config.Load(opts.configPath)
	add("config", loadErr, "valid configuration")
	if loadErr == nil {
		auditDir, resolveErr := resolveAuditDir(cfg, opts.dataDir)
		add("audit_path", resolveErr, "resolved")
		if resolveErr == nil {
			add("audit", verifyWritableAuditDir(auditDir, cfg.Limits.MaxAuditBytes), "hash chain and storage valid")
			_, identityErr := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
			add("identity", identityErr, "signing key valid")
		}
		if len(cfg.Identity.Peers) == 0 {
			add("peers", errors.New("no peer public keys configured"), "")
		} else {
			add("peers", nil, fmt.Sprintf("%d configured", len(cfg.Identity.Peers)))
		}
		if cfg.Guard.APIKeyEnv != "" {
			value, exists := os.LookupEnv(cfg.Guard.APIKeyEnv)
			if !exists || value == "" {
				add("api_key", guard.ErrMissingAPIKey, "")
			} else {
				add("api_key", nil, "configured")
			}
		}
		if probe && report.OK {
			modelGuard, guardErr := guard.NewHTTP(guard.HTTPConfig{Endpoint: cfg.Guard.Endpoint, Model: cfg.Guard.Model, APIKeyEnv: cfg.Guard.APIKeyEnv, PromptCacheRetention: cfg.Guard.PromptCacheRetention, Timeout: 30 * time.Second})
			if guardErr == nil {
				probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_, guardErr = modelGuard.Evaluate(probeCtx, guard.Input{Direction: "outbound", Source: cfg.Identity.Name, Destination: cfg.Identity.Peers[0].Name, Text: probeText, Policy: cfg.Guard.Policy})
				cancel()
			}
			add("guard_probe", guardErr, "structured verdict received")
		}
	}
	if asJSON {
		if err := writeJSONOutput(stdout, report); err != nil {
			return err
		}
	} else {
		for _, check := range report.Checks {
			if _, err := fmt.Fprintf(stdout, "%-14s %-4s %s\n", check.Name, strings.ToUpper(check.Status), check.Message); err != nil {
				return err
			}
		}
	}
	if !report.OK {
		return reportedError(errors.New("doctor found configuration problems"))
	}
	return nil
}

func verifyWritableAuditDir(dir string, max int64) error {
	log, err := openWritableAudit(dir, max)
	if err != nil {
		return err
	}
	return log.Close()
}
