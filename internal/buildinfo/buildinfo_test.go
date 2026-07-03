package buildinfo

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveUsesEmbeddedModuleAndVCSMetadata(t *testing.T) {
	build := &debug.BuildInfo{
		GoVersion: "go-test",
		Main:      debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.time", Value: "2026-06-28T12:34:56Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	got := resolve("", "", "", build, true)
	if got.Version != "v1.2.3" || got.Commit != "0123456789abcdef" ||
		got.BuildTime != "2026-06-28T12:34:56Z" || got.Modified == nil || !*got.Modified || got.GoVersion != "go-test" {
		t.Fatalf("resolve() = %#v", got)
	}
}

func TestResolveReleaseOverridesTakePrecedence(t *testing.T) {
	build := &debug.BuildInfo{
		GoVersion: "go-test",
		Main:      debug.Module{Version: "v1.0.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "embedded-revision"},
			{Key: "vcs.time", Value: "embedded-time"},
			{Key: "vcs.modified", Value: "false"},
		},
	}

	got := resolve("v9.0.0", "release-revision", "release-time", build, true)
	if got.Version != "v9.0.0" || got.Commit != "release-revision" || got.BuildTime != "release-time" ||
		got.Modified == nil || *got.Modified {
		t.Fatalf("resolve() = %#v", got)
	}
}

func TestResolveDevelopmentFallbacks(t *testing.T) {
	build := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
	got := resolve("", "", "", build, true)
	if got.Version != "dev" || got.Commit != "unknown" || got.BuildTime != "unknown" || got.Modified != nil {
		t.Fatalf("resolve() = %#v", got)
	}

	got = resolve("", "", "", nil, false)
	if got.Version != "dev" || got.Commit != "unknown" || got.BuildTime != "unknown" || got.Modified != nil || got.GoVersion == "" {
		t.Fatalf("resolve() without build info = %#v", got)
	}
}

func TestResolveDoesNotTreatUnknownVCSStateAsClean(t *testing.T) {
	build := &debug.BuildInfo{
		GoVersion: "go-test",
		Main:      debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.modified", Value: "unknown"},
		},
	}

	if got := resolve("", "", "", build, true); got.Modified != nil {
		t.Fatalf("resolve() Modified = %v, want unknown", *got.Modified)
	}
}

func TestInfoJSONOmitsUnknownButIncludesKnownCleanState(t *testing.T) {
	unknown, err := json.Marshal(Info{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unknown), `"modified"`) {
		t.Fatalf("unknown VCS state encoded as known: %s", unknown)
	}

	clean := false
	known, err := json.Marshal(Info{Modified: &clean})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(known), `"modified":false`) {
		t.Fatalf("known-clean VCS state omitted: %s", known)
	}
}
