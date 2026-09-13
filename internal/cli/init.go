package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/identity"
)

func runInit(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var force, allowRemote bool
	var identityName, deploymentID, endpoint, model, apiKeyEnv, policy, policyVersion, cacheRetention string
	flags.BoolVar(&force, "force", false, "replace an existing configuration")
	flags.StringVar(&identityName, "identity", "local", "endpoint identity name")
	flags.StringVar(&deploymentID, "deployment-id", "", "tunnel or app deployment identity")
	flags.StringVar(&endpoint, "endpoint", "", "OpenAI Responses endpoint")
	flags.StringVar(&model, "model", "", "guard model")
	flags.StringVar(&apiKeyEnv, "api-key-env", "", "API key environment variable")
	flags.StringVar(&policy, "policy", "", "channel policy")
	flags.StringVar(&policyVersion, "policy-version", "", "policy version")
	flags.StringVar(&cacheRetention, "prompt-cache-retention", "", "in_memory or 24h")
	flags.BoolVar(&allowRemote, "allow-remote", false, "permit a remote HTTPS endpoint")
	rest, help, err := parseFlags(flags, args, stdout, initHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}

	cfg := config.Default()
	cfg.Identity.Name = identityName
	cfg.Deployment.ID = identityName
	if deploymentID != "" {
		cfg.Deployment.ID = deploymentID
	}
	if endpoint != "" {
		cfg.Guard.Endpoint = endpoint
	}
	if model != "" {
		cfg.Guard.Model = model
		if model == "gpt-5.5-2026-04-23" && cacheRetention == "" {
			cfg.Guard.PromptCacheRetention = "24h"
		}
	}
	if apiKeyEnv != "" {
		cfg.Guard.APIKeyEnv = apiKeyEnv
	}
	if policy != "" {
		cfg.Guard.Policy = policy
	}
	if policyVersion != "" {
		cfg.Guard.PolicyVersion = policyVersion
	}
	if cacheRetention != "" {
		cfg.Guard.PromptCacheRetention = cacheRetention
	}
	if allowRemote {
		cfg.Guard.AllowRemote = true
	}

	configPath := opts.configPath
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	if configPath == "" {
		return errors.New("cannot determine the default config path; use --config")
	}
	cfg.AuditDir, err = resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return usageError("%v", err)
	}
	log, err := openWritableAudit(cfg.AuditDir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return fmt.Errorf("initialize audit log: %w", err)
	}
	defer log.Close()
	signer, err := identity.LoadOrCreate(cfg.AuditDir, cfg.Identity.Name, true)
	if err != nil {
		return fmt.Errorf("initialize identity: %w", err)
	}
	approvalStore, err := approval.Open(cfg.AuditDir, true)
	if err != nil {
		return fmt.Errorf("initialize approvals: %w", err)
	}
	defer approvalStore.Close()
	aliasesAudit, err := log.AliasesPath(configPath)
	if err != nil {
		return fmt.Errorf("validate config path: %w", err)
	}
	if aliasesAudit {
		return errors.New("config path must not name the audit log")
	}
	guardDestination := func(parent *os.File, name string) error {
		aliasesState, guardErr := log.AliasesDirectory(parent)
		if guardErr != nil {
			return guardErr
		}
		aliasesApprovals, guardErr := approvalStore.AliasesDirectory(parent)
		if guardErr != nil {
			return guardErr
		}
		if aliasesState || aliasesApprovals {
			return errors.New("config path must be outside Turnwire state directories")
		}
		aliases, guardErr := log.AliasesEntry(parent, name)
		if guardErr != nil {
			return guardErr
		}
		if aliases {
			return errors.New("config path must not name the audit log")
		}
		return nil
	}
	if err := config.WriteGuarded(configPath, cfg, force, guardDestination); err != nil {
		return err
	}
	if !opts.quiet {
		lines := []string{
			"Initialized Turnwire\n",
			fmt.Sprintf("Identity: %s\n", strconv.Quote(cfg.Identity.Name)),
			fmt.Sprintf("Public key: %s\n", signer.PublicKey()),
			fmt.Sprintf("Config: %s\n", strconv.Quote(configPath)),
			fmt.Sprintf("Audit:  %s\n", strconv.Quote(cfg.AuditDir)),
			"Next: exchange public keys, run `turnwire peer add`, then `turnwire doctor --probe`\n",
		}
		for _, line := range lines {
			if err := writeOutput(stdout, []byte(line)); err != nil {
				return err
			}
		}
	}
	return nil
}
