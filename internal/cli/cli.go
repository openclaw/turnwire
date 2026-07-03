// Package cli implements the turnwire command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/openclaw/turnwire/internal/buildinfo"
)

type options struct {
	configPath string
	dataDir    string
	quiet      bool
	verbose    bool
	version    bool
}

type commandError struct {
	code     int
	err      error
	reported bool
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }

func usageError(format string, args ...any) error {
	return &commandError{code: 2, err: fmt.Errorf(format, args...)}
}

func reportedError(err error) error {
	return &commandError{code: 1, err: err, reported: true}
}

// Run executes one CLI invocation and returns its process exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, rest, help, err := parseGlobal(args)
	if err != nil {
		writeError(stderr, err)
		return 2
	}
	if opts.version {
		if len(rest) != 0 {
			writeError(stderr, errors.New("--version does not accept a command"))
			return 2
		}
		if err := writeOutput(stdout, []byte(versionLine())); err != nil {
			writeError(stderr, fmt.Errorf("write version: %w", err))
			return 1
		}
		return 0
	}
	if help || len(rest) == 0 {
		if err := writeRootHelp(stdout); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if opts.quiet && opts.verbose {
		writeError(stderr, errors.New("--quiet and --verbose cannot be used together"))
		return 2
	}

	command := rest[0]
	commandArgs := rest[1:]
	switch command {
	case "help":
		err = runHelp(commandArgs, stdout)
	case "init":
		err = runInit(commandArgs, opts, stdout)
	case "serve":
		err = runServe(ctx, commandArgs, opts, stdin, stdout, stderr)
	case "doctor":
		err = runDoctor(ctx, commandArgs, opts, stdout)
	case "log":
		err = runLog(commandArgs, opts, stdout)
	case "version":
		err = runVersion(commandArgs, stdout)
	default:
		err = usageError("unknown command %q", command)
	}
	if err == nil {
		return 0
	}

	var commandErr *commandError
	if errors.As(err, &commandErr) {
		if !commandErr.reported {
			writeError(stderr, commandErr.err)
		}
		return commandErr.code
	}
	writeError(stderr, err)
	return 1
}

func parseGlobal(args []string) (options, []string, bool, error) {
	var opts options
	var help bool
	flags := flag.NewFlagSet("turnwire", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.configPath, "config", "", "path to JSON configuration")
	flags.StringVar(&opts.dataDir, "data-dir", "", "directory for local state")
	flags.BoolVar(&opts.quiet, "quiet", false, "suppress nonessential status output")
	flags.BoolVar(&opts.verbose, "verbose", false, "show diagnostic output")
	flags.BoolVar(&opts.version, "version", false, "print build information")
	flags.BoolVar(&help, "help", false, "show help")
	flags.BoolVar(&help, "h", false, "show help")
	if err := flags.Parse(args); err != nil {
		return options{}, nil, false, err
	}
	return opts, flags.Args(), help, nil
}

func parseFlags(flags *flag.FlagSet, args []string, usage io.Writer, helpText string) ([]string, bool, error) {
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if writeErr := writeOutput(usage, []byte(helpText)); writeErr != nil {
				return nil, false, fmt.Errorf("write help: %w", writeErr)
			}
			return nil, true, nil
		}
		return nil, false, usageError("%v", err)
	}
	return flags.Args(), false, nil
}

func requireNoArgs(args []string) error {
	if len(args) != 0 {
		return usageError("unexpected argument %q", args[0])
	}
	return nil
}

func writeError(w io.Writer, err error) {
	fmt.Fprintf(w, "error: %v\n", err)
}

func runHelp(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return writeRootHelp(stdout)
	}
	if len(args) != 1 {
		return usageError("usage: turnwire help [command]")
	}
	text, ok := commandHelp(args[0])
	if !ok {
		return usageError("unknown command %q", args[0])
	}
	if err := writeOutput(stdout, []byte(text)); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return nil
}

func writeRootHelp(w io.Writer) error {
	if err := writeOutput(w, []byte(rootHelp)); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return nil
}

func writeOutput(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func commandHelp(command string) (string, bool) {
	switch command {
	case "init":
		return initHelp, true
	case "serve":
		return serveHelp, true
	case "doctor":
		return doctorHelp, true
	case "log":
		return logHelp, true
	case "version":
		return versionHelp, true
	case "help":
		return "Usage: turnwire help [command]\n", true
	default:
		return "", false
	}
}

const rootHelp = `Turnwire is an audited, text-only MCP bridge to a paired language model.

Usage:
  turnwire [global flags] <command> [flags]

Commands:
  init       Write a safe configuration and create the audit directory
  serve      Serve the talk tool over MCP stdio
  doctor     Check configuration, audit integrity, and optional model access
  log        List, show, or verify audited exchanges
  version    Print build information
  help       Show help for a command

Global flags (must appear before the command):
  --config PATH    JSON configuration path
  --data-dir PATH  Local state directory
  --quiet          Suppress nonessential status output
  --verbose        Show diagnostic output
  --version        Print build information
  -h, --help       Show this help
`

const initHelp = `Usage:
  turnwire [global flags] init [flags]

Flags:
  --force            Replace an existing configuration
  --endpoint URL     Chat Completions-compatible endpoint
  --model NAME       Model name
  --api-key-env NAME Environment variable containing the provider API key
  --allow-remote     Permit a remote HTTPS endpoint
`

const serveHelp = `Usage:
  turnwire [global flags] serve

Runs one MCP server over stdin/stdout. Protocol output is the only stdout output.
`

const doctorHelp = `Usage:
  turnwire [global flags] doctor [--probe] [--json]

Flags:
  --probe  Send a fixed connectivity probe to the configured model
  --json   Emit a machine-readable report
`

const logHelp = `Usage:
  turnwire [global flags] log list [--conversation ID] [--limit N] [--json]
  turnwire [global flags] log show ID [--json]
  turnwire [global flags] log verify [--json]
`

const versionHelp = `Usage:
  turnwire version [--json]
`

func versionLine() string {
	return formatVersionLine(buildinfo.Current())
}

func formatVersionLine(info buildinfo.Info) string {
	parts := []string{"turnwire", info.Version}
	details := []string{info.Commit}
	if info.Modified != nil {
		if *info.Modified {
			details = append(details, "modified")
		} else {
			details = append(details, "clean")
		}
	}
	details = append(details, "built "+info.BuildTime, info.GoVersion)
	return strings.Join(parts, " ") + " (" + strings.Join(details, ", ") + ")\n"
}
