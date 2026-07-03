package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestAppendReadAllPreservesExactUnicodeAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	text := "precomposed caf\u00e9 / decomposed cafe\u0301\r\nemoji: \U0001f9d1\U0001f3fd\u200d\U0001f4bb\nquotes: \\\" <>& \u2028"
	entry, err := log.Append(testEvent("event-1", text))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Text != text || len(entry.Text) != len(text) || !utf8.ValidString(entry.Text) {
		t.Fatalf("text changed during append: got %q, want %q", entry.Text, text)
	}
	if !strings.HasSuffix(entry.Timestamp, "Z") {
		t.Fatalf("timestamp is not UTC: %q", entry.Timestamp)
	}
	if entry.PreviousHash != genesisHash {
		t.Fatalf("first previous hash = %q, want genesis hash", entry.PreviousHash)
	}

	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Text != text {
		t.Fatalf("read text changed: %#v", entries)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	var scanned []string
	if err := log.Scan(func(entry Entry) error {
		scanned = append(scanned, entry.Text)
		return nil
	}); err != nil {
		t.Fatalf("Scan() = %v", err)
	}
	if len(scanned) != 1 || scanned[0] != text {
		t.Fatalf("scanned text changed: %#v", scanned)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
}

func TestEntryReferencesSupportVerifiedIndexedReads(t *testing.T) {
	log, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	first, firstReference, err := log.AppendWithReference(testEvent("event-1", "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, secondReference, err := log.AppendWithReference(testEvent("event-2", "second reply \U0001f30d"))
	if err != nil {
		t.Fatal(err)
	}
	if firstReference.offset != 0 || firstReference.length <= 1 ||
		firstReference.seq != first.Seq || firstReference.entryHash != first.EntryHash {
		t.Fatalf("first reference = %#v for entry %#v", firstReference, first)
	}
	if secondReference.offset != firstReference.length ||
		secondReference.seq != second.Seq || secondReference.entryHash != second.EntryHash {
		t.Fatalf("second reference = %#v after %#v", secondReference, firstReference)
	}

	var scanned []EntryReference
	if err := log.ScanWithReferences(func(_ Entry, reference EntryReference) error {
		scanned = append(scanned, reference)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 2 || scanned[0] != firstReference || scanned[1] != secondReference {
		t.Fatalf("scanned references = %#v, want %#v, %#v", scanned, firstReference, secondReference)
	}
	got, err := log.ReadReference(secondReference)
	if err != nil {
		t.Fatal(err)
	}
	if got != second {
		t.Fatalf("referenced entry = %#v, want %#v", got, second)
	}

	wrongIdentity := secondReference
	wrongIdentity.entryHash = first.EntryHash
	if _, err := log.ReadReference(wrongIdentity); err == nil {
		t.Fatal("ReadReference accepted a mismatched entry identity")
	}
	outside := secondReference
	outside.offset++
	if _, err := log.ReadReference(outside); err == nil {
		t.Fatal("ReadReference accepted a reference past the verified boundary")
	}
}

func TestScanRejectsCRLFInsteadOfDriftingReferenceOffsets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(testEvent("event-1", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(testEvent("event-2", "second")); err != nil {
		t.Fatal(err)
	}
	path := log.Path()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	crlf := strings.ReplaceAll(string(raw), "\n", "\r\n")
	if err := os.WriteFile(path, []byte(crlf), 0o600); err != nil {
		t.Fatal(err)
	}

	if reopened, err := Open(dir); err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted noncanonical CRLF audit records")
	}
}

func TestConcurrentAppendProducesSingleValidChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	const count = 128
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, appendErr := log.Append(testEvent(fmt.Sprintf("event-%03d", i), fmt.Sprintf("text-%03d", i)))
			errs <- appendErr
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != count {
		t.Fatalf("entry count = %d, want %d", len(entries), count)
	}
	previousHash := genesisHash
	seen := make(map[string]bool, count)
	for i, entry := range entries {
		if entry.Seq != uint64(i+1) {
			t.Fatalf("entry %d sequence = %d", i, entry.Seq)
		}
		if entry.PreviousHash != previousHash {
			t.Fatalf("entry %d previous hash does not link", i)
		}
		if seen[entry.EventID] {
			t.Fatalf("duplicate event ID %q", entry.EventID)
		}
		seen[entry.EventID] = true
		previousHash = entry.EntryHash
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("Log.Verify() = %v", err)
	}
}

func TestTamperingIsDetectedAndOpenRefusesLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append(testEvent(fmt.Sprintf("event-%d", i), fmt.Sprintf("original-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries[1].Text = "tampered"
	file, err := os.OpenFile(filepath.Join(dir, FileName), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	for _, entry := range entries {
		line, marshalErr := json.Marshal(entry)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Verify(dir); err == nil {
		t.Fatal("Verify() accepted a modified entry")
	}
	if reopened, err := Open(dir); err == nil {
		_ = reopened.Close()
		t.Fatal("Open() accepted a modified entry")
	}
}

func TestTruncatedEntryIsDetected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(testEvent("event-1", "reply")); err != nil {
		t.Fatal(err)
	}
	path := log.Path()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content[:len(content)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("Verify() = %v, want incomplete-entry error", err)
	}
}

func TestReopenContinuesVerifiedChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry1, err := first.Append(testEvent("event-1", "one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	entry2, err := second.Append(testEvent("event-2", "two"))
	if err != nil {
		t.Fatal(err)
	}
	if entry2.Seq != 2 || entry2.PreviousHash != entry1.EntryHash {
		t.Fatalf("chain was not continued: %#v", entry2)
	}
}

func TestOpenRejectsConcurrentWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(dir)
	if second != nil {
		_ = second.Close()
		t.Fatal("second Open returned a writer")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open error = %v, want ErrLocked", err)
	}
	if err := Verify(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("free Verify during live writer = %v, want ErrLocked", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsBroadExistingDirectoryWithoutChangingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if log, err := Open(dir); err == nil {
		_ = log.Close()
		t.Fatal("Open accepted a broadly accessible existing directory")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("Open changed existing directory mode to %o", got)
	}
}

func TestOpenRejectsUnsafeAuditFileEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix filesystem security test")
	}
	t.Run("symbolic link", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "audit")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		if log, err := Open(dir); err == nil {
			_ = log.Close()
			t.Fatal("Open accepted a symbolic-link audit file")
		}
	})

	t.Run("broad permissions", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "audit")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, FileName)
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if log, err := Open(dir); err == nil {
			_ = log.Close()
			t.Fatal("Open accepted a broadly accessible audit file")
		}
	})
}

func TestAuditFileOpenRemainsAnchoredWhenDirectoryPathChanges(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-relative open test")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	directory, _, err := openAuditDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	moved := filepath.Join(root, "moved-audit")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(root, "decoy")
	if err := os.WriteFile(decoy, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, filepath.Join(dir, FileName)); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	file, _, err := openAuditFile(directory, false, false)
	if err != nil {
		t.Fatalf("descriptor-relative open followed replacement path: %v", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(filepath.Join(moved, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(openedInfo, originalInfo) {
		t.Fatal("descriptor-relative open escaped the validated audit directory")
	}
}

func TestOpenRejectsNonStickyWritableAncestorEvenForExistingLog(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure ancestor traversal test")
	}
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(shared, "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if log, err := Open(dir); err == nil {
		_ = log.Close()
		t.Fatal("Open accepted an audit log replaceable through a non-sticky writable ancestor")
	} else if !strings.Contains(err.Error(), "without sticky-directory protection") {
		t.Fatalf("Open error = %v, want unsafe-ancestor rejection", err)
	}
}

func TestOpenAllowsStickyWritableAncestorAndReopensChain(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure ancestor traversal test")
	}
	root := t.TempDir()
	shared := filepath.Join(root, "sticky")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(shared, "audit")
	first, err := Open(dir)
	if err != nil {
		t.Fatalf("Open under sticky ancestor: %v", err)
	}
	entry, err := first.Append(testEvent("sticky-event", "durable"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen under sticky ancestor: %v", err)
	}
	defer second.Close()
	entries, err := second.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].EntryHash != entry.EntryHash {
		t.Fatalf("reopened entries = %#v, want committed sticky event", entries)
	}
}

func TestOpenSupportsSystemStickyTemporaryAncestor(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure ancestor traversal test")
	}
	stickyRoot := "/tmp"
	if runtime.GOOS == "darwin" {
		stickyRoot = "/private/tmp"
	}
	parent, err := os.MkdirTemp(stickyRoot, "turnwire-ancestor-test-")
	if err != nil {
		t.Skipf("cannot create system temporary test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	log, err := Open(filepath.Join(parent, "audit"))
	if err != nil {
		t.Fatalf("Open under system sticky temporary ancestor: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsFinalAuditDirectorySymlink(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure ancestor traversal test")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "audit")
	if err := os.Symlink(target, dir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if log, err := Open(dir); err == nil {
		_ = log.Close()
		t.Fatal("Open accepted a symbolic-link audit directory")
	}
}

func TestOpenResolvesProtectedAncestorSymlink(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure ancestor traversal test")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	log, err := Open(filepath.Join(alias, "audit"))
	if err != nil {
		t.Fatalf("Open through protected ancestor symlink: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "audit", FileName)); err != nil {
		t.Fatalf("resolved audit file: %v", err)
	}
}

func TestAppendRejectsInvalidUTF8WithoutWriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	event := testEvent("event-1", "ok")
	event.Text = string([]byte{0xff, 0xfe})
	if _, err := log.Append(event); err == nil {
		t.Fatal("Append() accepted invalid UTF-8")
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid event was written: %#v", entries)
	}
}

func TestQuotaRejectsBeforeWriteWithoutPoisoningHandle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	ops := defaultAuditIO()
	writeCalls := 0
	writeFile := ops.writeFile
	ops.writeFile = func(file *os.File, data []byte) error {
		writeCalls++
		return writeFile(file, data)
	}
	log, err := openWithQuotaAndIO(dir, 1024, ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	large := testEvent("large-event", strings.Repeat("x", 1024))
	if _, err := log.Append(large); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Append(large) error = %v, want ErrQuotaExceeded", err)
	} else if errors.Is(err, ErrUncertainDurability) {
		t.Fatalf("clean quota rejection reported uncertain durability: %v", err)
	}
	if writeCalls != 0 {
		t.Fatalf("write calls after quota rejection = %d, want 0", writeCalls)
	}
	usedBytes, maxBytes, err := log.Usage()
	if err != nil {
		t.Fatalf("Usage after quota rejection: %v", err)
	}
	if usedBytes != 0 || maxBytes != 1024 {
		t.Fatalf("Usage after quota rejection = %d/%d, want 0/1024", usedBytes, maxBytes)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("Verify after quota rejection: %v", err)
	}
	entries, err := log.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll after quota rejection: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after quota rejection = %#v, want none", entries)
	}

	entry, reference, err := log.AppendWithReference(testEvent("small-event", "small"))
	if err != nil {
		t.Fatalf("Append(small) after quota rejection: %v", err)
	}
	if entry.Seq != 1 {
		t.Fatalf("small entry sequence = %d, want 1", entry.Seq)
	}
	if writeCalls != 1 {
		t.Fatalf("write calls after small append = %d, want 1", writeCalls)
	}
	usedBytes, maxBytes, err = log.Usage()
	if err != nil || usedBytes <= 0 || usedBytes > maxBytes {
		t.Fatalf("Usage after small append = %d/%d, %v", usedBytes, maxBytes, err)
	}
	if _, err := log.Append(large); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second Append(large) error = %v, want ErrQuotaExceeded", err)
	}
	replayed, err := log.ReadReference(reference)
	if err != nil {
		t.Fatalf("ReadReference after clean quota rejection: %v", err)
	}
	if replayed != entry {
		t.Fatalf("ReadReference after quota rejection = %#v, want %#v", replayed, entry)
	}
}

func TestQuotaAllowsInspectionWhenExistingLogIsAtOrAboveLimit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	seed, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Append(testEvent("seed-event", "durable")); err != nil {
		t.Fatal(err)
	}
	path := seed.Path()
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, limit := range []int64{info.Size(), info.Size() - 1} {
		log, err := OpenWithQuota(dir, limit)
		if err != nil {
			t.Fatalf("OpenWithQuota(%d): %v", limit, err)
		}
		if _, err := log.Append(testEvent("rejected-event", "new")); !errors.Is(err, ErrQuotaExceeded) {
			_ = log.Close()
			t.Fatalf("Append with limit %d error = %v, want ErrQuotaExceeded", limit, err)
		}
		entries, err := log.ReadAll()
		if err != nil {
			_ = log.Close()
			t.Fatalf("ReadAll with limit %d: %v", limit, err)
		}
		if len(entries) != 1 || entries[0].EventID != "seed-event" {
			_ = log.Close()
			t.Fatalf("entries with limit %d = %#v", limit, entries)
		}
		if err := log.Verify(); err != nil {
			_ = log.Close()
			t.Fatalf("Verify with limit %d: %v", limit, err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("standalone ReadAll after quota exhaustion: %v", err)
	}
	if len(entries) != 1 || entries[0].EventID != "seed-event" {
		t.Fatalf("standalone entries = %#v", entries)
	}
}

func TestOpenWithQuotaRejectsNonPositiveLimitBeforeCreatingStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	for _, limit := range []int64{0, -1} {
		if log, err := OpenWithQuota(dir, limit); err == nil {
			_ = log.Close()
			t.Fatalf("OpenWithQuota(%d) succeeded", limit)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("audit directory after invalid quotas: %v", err)
	}
}

func TestClosedLogRejectsOperations(t *testing.T) {
	log, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	_, reference, err := log.AppendWithReference(testEvent("event-before-close", "text"))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(testEvent("event-1", "text")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append() error = %v, want ErrClosed", err)
	}
	if _, err := log.ReadAll(); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadAll() error = %v, want ErrClosed", err)
	}
	if err := log.Scan(func(Entry) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Scan() error = %v, want ErrClosed", err)
	}
	if err := log.ScanWithReferences(func(Entry, EntryReference) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("ScanWithReferences() error = %v, want ErrClosed", err)
	}
	if _, err := log.ReadReference(reference); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadReference() error = %v, want ErrClosed", err)
	}
	if _, _, err := log.Usage(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Usage() error = %v, want ErrClosed", err)
	}
}

func TestReadReferenceRejectsPoisonedHandle(t *testing.T) {
	injected := errors.New("injected sync failure")
	poisonSync := false
	ops := defaultAuditIO()
	ops.syncFile = func(file *os.File) error {
		if poisonSync {
			return injected
		}
		return file.Sync()
	}
	log, err := openWithIO(filepath.Join(t.TempDir(), "audit"), ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	_, reference, err := log.AppendWithReference(testEvent("durable", "durable reply"))
	if err != nil {
		t.Fatal(err)
	}
	poisonSync = true
	if _, err := log.Append(testEvent("uncertain", "uncertain append")); !errors.Is(err, injected) {
		t.Fatalf("poisoning Append error = %v, want injected failure", err)
	}
	if _, err := log.ReadReference(reference); !errors.Is(err, ErrUncertainDurability) {
		t.Fatalf("ReadReference on poisoned handle error = %v, want ErrUncertainDurability", err)
	}
}

func TestWriteOrSyncUncertaintyPoisonsHandleUntilVerifiedReopen(t *testing.T) {
	injected := errors.New("injected durability failure")
	tests := []struct {
		name   string
		mutate func(*auditIO)
	}{
		{
			name: "write reports failure after complete write",
			mutate: func(ops *auditIO) {
				ops.writeFile = func(file *os.File, data []byte) error {
					if err := writeAll(file, data); err != nil {
						return err
					}
					return injected
				}
			},
		},
		{
			name: "sync fails after complete write",
			mutate: func(ops *auditIO) {
				syncCalls := 0
				ops.syncFile = func(file *os.File) error {
					syncCalls++
					if syncCalls == 2 {
						return injected
					}
					return file.Sync()
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "audit")
			ops := defaultAuditIO()
			test.mutate(&ops)
			log, err := openWithIO(dir, ops)
			if err != nil {
				t.Fatal(err)
			}

			reply := testEvent("reply-event", "fully written reply")
			reply.Type = "reply"
			if _, err := log.Append(reply); err == nil || !errors.Is(err, injected) {
				t.Fatalf("Append() error = %v, want injected failure", err)
			}
			raw, err := os.ReadFile(log.Path())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(string(raw), "\n") || !strings.Contains(string(raw), "fully written reply") {
				t.Fatalf("injected failure did not follow a complete write: %q", raw)
			}

			assertUncertain := func(name string, err error) {
				t.Helper()
				if !errors.Is(err, ErrUncertainDurability) {
					t.Fatalf("%s error = %v, want ErrUncertainDurability", name, err)
				}
			}
			_, err = log.ReadAll()
			assertUncertain("ReadAll", err)
			visited := false
			err = log.Scan(func(Entry) error {
				visited = true
				return nil
			})
			assertUncertain("Scan", err)
			if visited {
				t.Fatal("Scan visited page-cache data after uncertain durability")
			}
			assertUncertain("Verify", log.Verify())
			_, err = log.AliasesPath(log.Path())
			assertUncertain("AliasesPath", err)
			directory, _, err := openAuditDirectory(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = log.AliasesEntry(directory, FileName)
			assertUncertain("AliasesEntry", err)
			if err := directory.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = log.Append(testEvent("retry-on-poisoned-handle", "retry"))
			assertUncertain("Append retry", err)
			if _, err := ReadAll(dir); !errors.Is(err, ErrLocked) {
				t.Fatalf("free ReadAll during uncertain live writer = %v, want ErrLocked", err)
			}

			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			freeEntries, err := ReadAll(dir)
			if err != nil {
				t.Fatalf("recovery ReadAll after close: %v", err)
			}
			if len(freeEntries) != 1 || freeEntries[0].Text != reply.Text {
				t.Fatalf("recovery ReadAll entries = %#v", freeEntries)
			}
			reopened, err := Open(dir)
			if err != nil {
				t.Fatalf("verified reopen: %v", err)
			}
			defer reopened.Close()
			entries, err := reopened.ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Text != reply.Text || entries[0].Type != "reply" {
				t.Fatalf("reopened entries = %#v, want fully written reply", entries)
			}
			retry, err := reopened.Append(testEvent("next-event", "retry after verified reopen"))
			if err != nil {
				t.Fatal(err)
			}
			if retry.Seq != 2 {
				t.Fatalf("retry sequence = %d, want 2", retry.Seq)
			}
		})
	}
}

func TestOpenAlwaysSyncsExistingDirectoryBeforeServing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	seed, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Append(testEvent("seed", "committed")); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected directory sync failure")
	ops := defaultAuditIO()
	syncCalls := 0
	ops.syncDirectory = func(*os.File) error {
		syncCalls++
		return injected
	}
	if log, err := openWithIO(dir, ops); err == nil {
		_ = log.Close()
		t.Fatal("Open served an existing directory after its sync failed")
	} else if !errors.Is(err, injected) {
		t.Fatalf("Open error = %v, want injected sync failure", err)
	}
	if syncCalls != 1 {
		t.Fatalf("directory sync calls = %d, want 1 for existing storage", syncCalls)
	}

	recovered, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after directory-sync recovery: %v", err)
	}
	defer recovered.Close()
	entries, err := recovered.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Text != "committed" {
		t.Fatalf("recovered entries = %#v", entries)
	}
}

func testEvent(eventID, text string) Event {
	return Event{
		EventID:        eventID,
		ExchangeID:     "exchange-1",
		RequestID:      "request-1",
		ConversationID: "conversation-1",
		Type:           "message",
		Status:         "ok",
		Text:           text,
	}
}
