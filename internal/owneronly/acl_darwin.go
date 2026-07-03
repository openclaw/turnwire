//go:build darwin && cgo

package owneronly

/*
#include <errno.h>
#include <sys/acl.h>

static int owneronly_acl_status(int fd, int *has_acl) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) {
			*has_acl = 0;
			return 0;
		}
		return errno == 0 ? EIO : errno;
	}
	// On macOS, absence is reported as NULL with ENOENT. A non-NULL extended
	// ACL therefore represents at least one access-control entry.
	acl_free(acl);
	*has_acl = 1;
	return 0;
}

static int owneronly_ancestor_acl_status(int fd, int *unsafe_acl) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		if (errno == ENOENT) {
			*unsafe_acl = 0;
			return 0;
		}
		return errno == 0 ? EIO : errno;
	}
	acl_entry_t entry;
	int entry_id = ACL_FIRST_ENTRY;
	for (;;) {
		errno = 0;
		int result = acl_get_entry(acl, entry_id, &entry);
		if (result < 0) {
			int saved_errno = errno;
			acl_free(acl);
			if (saved_errno == EINVAL) {
				*unsafe_acl = 0;
				return 0;
			}
			return saved_errno == 0 ? EIO : saved_errno;
		}
		acl_tag_t tag;
		if (acl_get_tag_type(entry, &tag) != 0) {
			int saved_errno = errno;
			acl_free(acl);
			return saved_errno == 0 ? EIO : saved_errno;
		}
		if (tag != ACL_EXTENDED_DENY) {
			acl_free(acl);
			*unsafe_acl = 1;
			return 0;
		}
		entry_id = ACL_NEXT_ENTRY;
	}
}
*/
import "C"

import (
	"os"
	"syscall"
)

func hasExtendedACL(file *os.File) (bool, error) {
	var present C.int
	errno := C.owneronly_acl_status(C.int(file.Fd()), &present)
	if errno != 0 {
		return false, syscall.Errno(errno)
	}
	return present != 0, nil
}

func hasUnsafeAncestorACL(file *os.File) (bool, error) {
	var unsafe C.int
	errno := C.owneronly_ancestor_acl_status(C.int(file.Fd()), &unsafe)
	if errno != 0 {
		return false, syscall.Errno(errno)
	}
	return unsafe != 0, nil
}
