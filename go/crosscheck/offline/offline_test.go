package offline

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

const (
	suite = "conformance/suites/offline-package"
	now   = "2026-10-01T00:00:00Z"
)

func repository(t *testing.T, relative string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", relative))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func policy(t *testing.T, relative string) *trust.Policy {
	t.Helper()
	loaded, err := trust.Load(repository(t, relative))
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func valid(t *testing.T) []byte {
	return repository(t, suite+"/package-valid-verified.zip")
}

func refusal(t *testing.T, data []byte, limits Limits) *ArchiveError {
	t.Helper()
	_, err := ReadArchive(data, limits)
	var refused *ArchiveError
	if !errors.As(err, &refused) {
		t.Fatalf("the archive was not refused: %v", err)
	}
	return refused
}

func with(change func(*Limits)) Limits {
	limits := DefaultLimits
	change(&limits)
	return limits
}

// rawArchive is the profile encoding of members in the order and with the names given, flagged as
// UTF-8 when not ASCII: what a producer that ignored the entry name rule would write.
func rawArchive(members []Member) []byte {
	var out, central []byte
	for _, member := range members {
		name := []byte(member.Name)
		flags := uint16(0)
		for _, character := range name {
			if character >= 0x80 {
				flags = 0x800
			}
		}
		entry := layoutMember{nameBytes: name, crc: crc32.ChecksumIEEE(member.Data), size: uint32(len(member.Data))}
		offset := uint32(len(out))
		local := appendLocal(nil, entry)
		binary.LittleEndian.PutUint16(local[6:], flags)
		out = append(append(out, local...), member.Data...)
		start := len(central)
		central = appendCentral(central, entry, offset)
		binary.LittleEndian.PutUint16(central[start+8:], flags)
	}
	directoryOffset := uint32(len(out))
	out = append(out, central...)
	return appendEnd(out, len(members), uint32(len(central)), directoryOffset)
}

func TestEveryPackageVectorGetsTheReferenceVerdict(t *testing.T) {
	raw := repository(t, suite+"/manifest.json")
	var decoded struct {
		Vectors []map[string]any `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, vector := range decoded.Vectors {
		var history []*trust.Policy
		for _, path := range vector["trust_policy_history_paths"].([]any) {
			history = append(history, policy(t, path.(string)))
		}
		report, err := Verify(repository(t, vector["path"].(string)), policy(t, vector["trust_policy_path"].(string)), Options{Options: evidence.Options{Now: vector["evaluated_at"].(string), History: history}})
		if err != nil {
			t.Fatalf("%v: %v", vector["id"], err)
		}
		if report.Verdict != vector["expected_verdict"] {
			t.Errorf("%v: verdict %s", vector["id"], report.Verdict)
		}
		found := Identifiers(report)
		if vector["expected"] == "pass" && len(found) != 0 {
			t.Errorf("%v: %v", vector["id"], found)
		}
		if primary, _ := vector["expected_primary_id"].(string); vector["expected"] == "fail" && !strings.Contains(strings.Join(found, " "), primary) {
			t.Errorf("%v: %v, want %s", vector["id"], found, primary)
		}
	}
	if len(decoded.Vectors) < 15 {
		t.Fatalf("%d vectors", len(decoded.Vectors))
	}
}

func TestTheReaderAndWriterAgreeOnAProfileArchive(t *testing.T) {
	data := valid(t)
	members, err := ReadArchive(data, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if members[0].Name != "evidence/envelope-01-payload.json" {
		t.Fatalf("first member %s", members[0].Name)
	}
	reversed := make([]Member, len(members))
	for index, member := range members {
		reversed[len(members)-1-index] = member
	}
	written, err := WriteArchive(reversed)
	if err != nil || !bytes.Equal(written, data) {
		t.Fatalf("the writer does not rebuild the archive: %v", err)
	}
	if _, err := WriteArchive([]Member{{Name: "café.json"}}); err == nil {
		t.Fatal("the writer accepted a name outside the portable set")
	}
}

func TestAnyChangedHeaderByteIsRefused(t *testing.T) {
	data, err := WriteArchive([]Member{{Name: "a.json", Data: []byte("{}")}, {Name: "b/c.json", Data: []byte("[]")}})
	if err != nil {
		t.Fatal(err)
	}
	first := 30 + len("a.json")
	second := first + 2 + 30 + len("b/c.json")
	content := map[int]bool{first: true, first + 1: true, second: true, second + 1: true}
	for position := range data {
		for _, bit := range []uint{0, 3, 7} {
			changed := append([]byte{}, data...)
			changed[position] ^= 1 << bit
			refused := refusal(t, changed, DefaultLimits)
			if content[position] && refused.Limit {
				t.Errorf("data byte %d: a limit", position)
			}
		}
	}
	for _, changed := range [][]byte{append([]byte("#!"), data...), append(append([]byte{}, data...), 0), {}, []byte("not an archive")} {
		if refusal(t, changed, DefaultLimits).Limit {
			t.Errorf("%q: a limit", changed[:min(len(changed), 8)])
		}
	}
}

func TestEntryNamesAndASCIIAliases(t *testing.T) {
	for _, name := range []string{"a.json", "evidence/envelope-01.json", ".hidden/x_y-z.1", "console.json", "com10.json", "A/B/C"} {
		if !IsEntryName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", "/a.json", "a//b.json", "a/", "./a.json", "../a.json", "a/../b.json", "trailing.", "a./b.json", "con", "NUL.txt", "a/Com1.json", "lpt9", "café.json", "a b.json", "a+b.json", "a:b.json", "a\\b.json", "~a.json", "control\x01.json"} {
		if IsEntryName(name) {
			t.Errorf("%q accepted", name)
		}
		if refusal(t, rawArchive([]Member{{Name: name, Data: []byte("{}")}}), DefaultLimits).Limit {
			t.Errorf("%q: a limit", name)
		}
	}
	if FoldASCII("Docs/README.MD") != "docs/readme.md" || FoldASCII("É.json") != "É.json" {
		t.Fatal("ASCII case folding")
	}
	for _, names := range [][]string{{"A.json", "a.json"}, {"Dir/File.json", "dir/file.json"}, {"docs", "Docs/a.json"}, {"a", "a/b.json"}} {
		members := []Member{}
		for _, name := range names {
			members = append(members, Member{Name: name, Data: []byte("{}")})
		}
		if refusal(t, rawArchive(members), DefaultLimits).Limit {
			t.Errorf("%v: a limit", names)
		}
	}
}

func TestMetadataOutsideTheProfileIsRefused(t *testing.T) {
	base, err := WriteArchive([]Member{{Name: "a.json", Data: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	central := 30 + 6 + 2
	for name, change := range map[string][2]int{
		"local encrypted": {6, 0x01}, "local descriptor": {6, 0x08}, "local UTF-8": {7, 0x08},
		"local method": {8, 0x08}, "local time": {10, 0x01}, "central made-by": {central + 5, 0},
		"central UTF-8": {central + 9, 0x08}, "central deflated": {central + 10, 0x08},
		"central date": {central + 14, 0x5a}, "central internal": {central + 36, 1}, "central executable": {central + 40, 0xed},
	} {
		changed := append([]byte{}, base...)
		changed[change[0]] = byte(change[1])
		if refusal(t, changed, DefaultLimits).Limit {
			t.Errorf("%s: a limit", name)
		}
	}
	commented := append(append(append([]byte{}, base[:len(base)-2]...), 4, 0), []byte("note")...)
	if refused := refusal(t, commented, DefaultLimits); !strings.Contains(refused.Message, "archive comment") {
		t.Errorf("comment: %s", refused.Message)
	}
}

func TestLimitsAreRefusedAsLimitsBeforeOtherMemberChecks(t *testing.T) {
	data := valid(t)
	members, err := ReadArchive(data, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var largest, total, longest int64
	for _, member := range members {
		largest = max(largest, int64(len(member.Data)))
		total += int64(len(member.Data))
		longest = max(longest, int64(len(member.Name)))
	}
	for name, limits := range map[string]Limits{
		"archive bytes": with(func(l *Limits) { l.MaxArchiveBytes = int64(len(data)) - 1 }),
		"member count":  with(func(l *Limits) { l.MaxMemberCount = int64(len(members)) - 1 }),
		"member size":   with(func(l *Limits) { l.MaxEntryUncompressedBytes = largest - 1 }),
		"total size":    with(func(l *Limits) { l.MaxTotalUncompressedBytes = total - 1 }),
		"path bytes":    with(func(l *Limits) { l.MaxPathBytes = longest - 1 }),
	} {
		if !refusal(t, data, limits).Limit {
			t.Errorf("%s: not a limit", name)
		}
	}
	if _, err := ReadArchive(data, Limits{int64(len(data)), int64(len(members)), largest, total, 1, longest}); err != nil {
		t.Fatalf("at the limits: %v", err)
	}
	bomb, err := WriteArchive([]Member{{Name: "bomb.bin", Data: make([]byte, 10)}})
	if err != nil {
		t.Fatal(err)
	}
	bomb[8] = 8
	bomb[30+8+10+10] = 8
	binary.LittleEndian.PutUint32(bomb[30+8+10+24:], 5_000)
	if !refusal(t, bomb, with(func(l *Limits) { l.MaxCompressionRatio = 10 })).Limit {
		t.Error("ratio: not a limit")
	}
	if refusal(t, bomb, DefaultLimits).Limit {
		t.Error("deflated: a limit")
	}
	misnamed := rawArchive([]Member{{Name: "a b.json", Data: make([]byte, 100)}})
	if !refusal(t, misnamed, with(func(l *Limits) { l.MaxEntryUncompressedBytes = 10 })).Limit {
		t.Error("a limit does not come first")
	}
	if _, err := ReadArchive(data, with(func(l *Limits) { l.MaxMemberCount = 0 })); !errors.Is(err, ErrInvalidLimits) {
		t.Errorf("invalid limits: %v", err)
	}
}

func TestAPackageOverALimitIsInvalidWithTheLimitError(t *testing.T) {
	limits := with(func(l *Limits) { l.MaxArchiveBytes = 100 })
	report, err := Verify(valid(t), policy(t, suite+"/trust-policy.json"), Options{Options: evidence.Options{Now: now}, Limits: &limits})
	if err != nil || report.Verdict != evidence.Invalid || strings.Join(Identifiers(report), " ") != ResourceLimitExceeded {
		t.Fatalf("check 1: %v %v", report, err)
	}
	members, err := ReadArchive(valid(t), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for index, member := range members {
		if member.Name != ManifestName {
			continue
		}
		var manifest map[string]any
		if err := json.Unmarshal(member.Data, &manifest); err != nil {
			t.Fatal(err)
		}
		artifacts := manifest["artifacts"].([]any)
		extra := map[string]any{}
		for key, value := range artifacts[0].(map[string]any) {
			extra[key] = value
		}
		extra["path"] = "material/" + strings.Repeat("x", 80) + ".json"
		extra["role"] = "trust_root"
		manifest["artifacts"] = append(artifacts, extra)
		members[index].Data, _ = json.Marshal(manifest)
	}
	longPath, err := WriteArchive(members)
	if err != nil {
		t.Fatal(err)
	}
	short := with(func(l *Limits) { l.MaxPathBytes = 64 })
	report, err = Verify(longPath, policy(t, suite+"/trust-policy.json"), Options{Options: evidence.Options{Now: now}, Limits: &short})
	if err != nil || report.Verdict != evidence.Invalid || strings.Join(Identifiers(report), " ") != ResourceLimitExceeded {
		t.Fatalf("check 4: %v %v", report, err)
	}
	report, err = Verify(longPath, policy(t, suite+"/trust-policy.json"), Options{Options: evidence.Options{Now: now}})
	if err != nil || report.Verdict != evidence.Incomplete {
		t.Fatalf("without the lower limit: %v %v", report, err)
	}
}

func TestTheBundleOptionsReachThePackageBundleUnchanged(t *testing.T) {
	data := valid(t)
	revoked := policy(t, suite+"/trust-policy-revoked-after-use.json")
	history := []*trust.Policy{policy(t, suite+"/trust-policy.json")}
	report, err := Verify(data, revoked, Options{Options: evidence.Options{Now: now, History: history}})
	if err != nil || report.Verdict != evidence.CurrentTrustFailed {
		t.Fatalf("revoked: %v %v", report, err)
	}
	report, err = Verify(data, revoked, Options{Options: evidence.Options{Now: now, History: history, AcceptCurrentTrustFailure: true}})
	if err != nil || report.Verdict != evidence.Verified || !report.AcceptedCurrentTrustFailure {
		t.Fatalf("accepted: %v %v", report, err)
	}
	report, err = Verify(data, history[0], Options{Options: evidence.Options{Now: now, RequireTrustedTime: true}})
	if err != nil || report.Verdict != evidence.Invalid || report.VerificationProfile != evidence.TrustedTimeProfile || !strings.Contains(strings.Join(Identifiers(report), " "), "ecl.error.trusted-time-required.v1") {
		t.Fatalf("trusted time: %v %v", report, err)
	}
	early, err := Verify([]byte("not an archive"), history[0], Options{Options: evidence.Options{Now: now, RequireTrustedTime: true}})
	if err != nil || early.VerificationProfile != evidence.TrustedTimeProfile || strings.Join(Identifiers(early), " ") != semanticInvalid {
		t.Fatalf("early refusal: %v %v", early, err)
	}
}

func TestCallerArgumentsAreCheckedBeforeThePackageIsRead(t *testing.T) {
	trusted := policy(t, suite+"/trust-policy.json")
	zero := Limits{}
	for _, data := range [][]byte{valid(t), []byte("not an archive")} {
		if _, err := Verify(data, trusted, Options{Options: evidence.Options{Now: "2026-10-01T00:00:00.5Z"}}); !errors.Is(err, evidence.ErrInvalidNow) {
			t.Errorf("now: %v", err)
		}
		if _, err := Verify(data, trusted, Options{Options: evidence.Options{Now: now, ResponseClockSkewSeconds: -1}}); !errors.Is(err, evidence.ErrNegativeSkew) {
			t.Errorf("skew: %v", err)
		}
		if _, err := Verify(data, trusted, Options{Options: evidence.Options{Now: now}, Limits: &zero}); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("limits: %v", err)
		}
	}
}

// centralDirectory is an archive of count central directory entries named "a" and an end record;
// the entry at corruptAt, when it is not negative, has a wrong signature.
func centralDirectory(count, corruptAt int) []byte {
	data := make([]byte, 0, 47*count+22)
	for index := 0; index < count; index++ {
		entry := make([]byte, 47)
		signature := uint32(0x02014b50)
		if index == corruptAt {
			signature = 0x58585858
		}
		binary.LittleEndian.PutUint32(entry[0:], signature)
		binary.LittleEndian.PutUint16(entry[4:], (3<<8)|20)
		binary.LittleEndian.PutUint16(entry[6:], 20)
		binary.LittleEndian.PutUint16(entry[14:], 33)
		binary.LittleEndian.PutUint16(entry[28:], 1)
		binary.LittleEndian.PutUint32(entry[38:], 0o100644<<16)
		entry[46] = 'a'
		data = append(data, entry...)
	}
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(count))
	binary.LittleEndian.PutUint16(end[10:], uint16(count))
	binary.LittleEndian.PutUint32(end[12:], uint32(47*count))
	return append(data, end...)
}

// IE1-029: the reader keeps no more central directory entries than its member limit, and still
// reads the whole directory before it compares the count, as the reference does.
func TestTheReaderKeepsNoMoreEntriesThanTheMemberLimit(t *testing.T) {
	limits := DefaultLimits
	limits.MaxMemberCount = 10
	data := centralDirectory(300_000, -1)
	var refusal *ArchiveError
	allocated := testing.AllocsPerRun(2, func() {
		_, err := ReadArchive(data, limits)
		if !errors.As(err, &refusal) || !refusal.Limit || !strings.Contains(refusal.Message, "member count") {
			t.Fatalf("%v", err)
		}
	})
	if allocated > 64 {
		t.Errorf("%d allocations for an archive of 300,000 directory entries under a limit of 10", int(allocated))
	}
	_, err := ReadArchive(centralDirectory(30, 25), limits)
	if !errors.As(err, &refusal) || refusal.Limit {
		t.Errorf("a directory that cannot be read beyond the limit: %v", err)
	}
}
