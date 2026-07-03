package owneronly

import "errors"

// ErrNotSymlink indicates that a descriptor-relative entry exists but is not a
// symbolic link.
var ErrNotSymlink = errors.New("path entry is not a symbolic link")
