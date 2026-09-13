package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/openclaw/turnwire/internal/identifier"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/config"
)

func runApprove(args []string, opts options, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("approve", flag.ContinueOnError)
	var yes bool
	flags.BoolVar(&yes, "yes", false, "approve without interactive confirmation")
	rest, help, err := parseFlags(flags, args, stdout, approveHelp)
	if err != nil || help {
		return err
	}
	if len(rest) != 1 || !identifier.Valid(rest[0]) {
		return usageError("usage: turnwire approve [--yes] MESSAGE_ID")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	store, err := approval.Open(auditDir, false)
	if err != nil {
		return err
	}
	defer store.Close()
	pending, err := store.Pending(rest[0])
	if err != nil {
		return err
	}
	display := fmt.Sprintf("Message: %s\nDirection: %s (%s -> %s)\nSHA-256: %s\nBody: %s\n", pending.MessageID, pending.Direction, pending.Source, pending.Destination, pending.BodySHA256, strconv.QuoteToASCII(pending.Body))
	if err := writeOutput(stdout, []byte(display)); err != nil {
		return fmt.Errorf("display pending approval: %w", err)
	}
	if !yes {
		if err := writeOutput(stdout, []byte("\nApprove this exact message? [y/N] ")); err != nil {
			return fmt.Errorf("display approval prompt: %w", err)
		}
		line, readErr := bufio.NewReader(io.LimitReader(stdin, 16)).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.TrimSpace(strings.ToLower(line)) != "y" && strings.TrimSpace(strings.ToLower(line)) != "yes" {
			return errors.New("approval canceled")
		}
	}
	if err := store.Approve(pending.Binding(), time.Now()); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Approved; retry the same Turnwire tool call.")
	return err
}
