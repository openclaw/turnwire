package owneronly

// DirectoryPolicy selects validation for the final directory descriptor.
type DirectoryPolicy uint8

const (
	// DirectoryOwnerOnly requires no group/other permissions.
	DirectoryOwnerOnly DirectoryPolicy = iota
	// DirectoryOwnerControlled permits group/other read and traversal, but not
	// write access. Extended ACLs remain forbidden.
	DirectoryOwnerControlled
)
