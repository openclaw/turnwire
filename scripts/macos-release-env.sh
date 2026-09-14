# Source this file when building macOS release binaries with Go 1.26.
# cgo is required for owner-only ACL validation.
export CGO_ENABLED=1
export MACOSX_DEPLOYMENT_TARGET=12.0
export CGO_CFLAGS="-O2 -g -mmacosx-version-min=12.0"
export CGO_LDFLAGS="-mmacosx-version-min=12.0"
