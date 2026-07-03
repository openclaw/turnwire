package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Version, Commit, and BuildTime are optional release-build overrides. Normal
// builds leave them empty and use the module and VCS metadata embedded by Go.
var (
	Version   string
	Commit    string
	BuildTime string
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	// Modified is absent when the Go toolchain did not embed a vcs.modified
	// setting. A nil value must not be interpreted as a clean checkout.
	Modified  *bool  `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
}

func Current() Info {
	build, ok := debug.ReadBuildInfo()
	return resolve(Version, Commit, BuildTime, build, ok)
}

func resolve(versionOverride, commitOverride, timeOverride string, build *debug.BuildInfo, ok bool) Info {
	info := Info{
		Version:   "dev",
		Commit:    "unknown",
		BuildTime: "unknown",
		GoVersion: runtime.Version(),
	}
	if ok && build != nil {
		if build.Main.Version != "" && build.Main.Version != "(devel)" {
			info.Version = build.Main.Version
		}
		if build.GoVersion != "" {
			info.GoVersion = build.GoVersion
		}
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				if setting.Value != "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if setting.Value != "" {
					info.BuildTime = setting.Value
				}
			case "vcs.modified":
				switch setting.Value {
				case "true":
					modified := true
					info.Modified = &modified
				case "false":
					modified := false
					info.Modified = &modified
				}
			}
		}
	}
	if versionOverride != "" {
		info.Version = versionOverride
	}
	if commitOverride != "" {
		info.Commit = commitOverride
	}
	if timeOverride != "" {
		info.BuildTime = timeOverride
	}
	return info
}
