package offline

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/bits"
	"strings"
	"unicode/utf8"
)

// Limits are the declared resource limits of an offline-package verifier (IE1-028). Every limit
// is a positive integer.
type Limits struct {
	// MaxArchiveBytes bounds the archive's bytes.
	MaxArchiveBytes int64
	// MaxMemberCount bounds the archive's members and the manifest's artifacts.
	MaxMemberCount int64
	// MaxEntryUncompressedBytes bounds the declared size of one member.
	MaxEntryUncompressedBytes int64
	// MaxTotalUncompressedBytes bounds the declared sizes of all members together.
	MaxTotalUncompressedBytes int64
	// MaxCompressionRatio bounds a member's declared size over its stored size.
	MaxCompressionRatio int64
	// MaxPathBytes bounds the bytes of one entry name or artifact path.
	MaxPathBytes int64
}

// DefaultLimits are the reference verifier's limits (ecl_reference.offline).
var DefaultLimits = Limits{
	MaxArchiveBytes:           1024 * 1024 * 1024,
	MaxMemberCount:            100_000,
	MaxEntryUncompressedBytes: 512 * 1024 * 1024,
	MaxTotalUncompressedBytes: 4 * 1024 * 1024 * 1024,
	MaxCompressionRatio:       1_000,
	MaxPathBytes:              4_096,
}

// ErrInvalidLimits is a limit that is not a positive integer.
var ErrInvalidLimits = errors.New("every offline resource limit is a positive integer")

func (l Limits) check() error {
	for _, value := range []int64{l.MaxArchiveBytes, l.MaxMemberCount, l.MaxEntryUncompressedBytes, l.MaxTotalUncompressedBytes, l.MaxCompressionRatio, l.MaxPathBytes} {
		if value < 1 {
			return ErrInvalidLimits
		}
	}
	return nil
}

// ArchiveError is an archive refused at the first check of IE1-022: outside the
// ecl.zip.store.v1 profile, or, when Limit is true, over a declared limit of the verifier.
type ArchiveError struct {
	Message string
	Limit   bool
}

func (e *ArchiveError) Error() string { return e.Message }

// Member is one member of an archive in profile form: its entry name and its bytes.
type Member struct {
	Name string
	Data []byte
}

// PortableNameCharacters are the POSIX portable filename characters, of which every component of
// an entry name consists.
const PortableNameCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

var deviceNames = func() map[string]bool {
	names := map[string]bool{"con": true, "prn": true, "aux": true, "nul": true}
	for digit := '0'; digit <= '9'; digit++ {
		names["com"+string(digit)] = true
		names["lpt"+string(digit)] = true
	}
	return names
}()

// FoldASCII returns name in ASCII lower case: the form under which two entry names are aliases.
func FoldASCII(name string) string {
	folded := []byte(name)
	for index, character := range folded {
		if 'A' <= character && character <= 'Z' {
			folded[index] = character + ('a' - 'A')
		}
	}
	return string(folded)
}

func portableComponent(part string) bool {
	if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") {
		return false
	}
	for index := 0; index < len(part); index++ {
		if !strings.ContainsRune(PortableNameCharacters, rune(part[index])) || part[index] >= 0x80 {
			return false
		}
	}
	stem, _, _ := strings.Cut(part, ".")
	return !deviceNames[FoldASCII(stem)]
}

// IsEntryName reports whether name is an entry name of ecl.zip.store.v1: components separated by
// "/", each of the POSIX portable filename characters, none "." or "..", none ending in ".", and
// none a Windows device name (CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9) in any letter case
// before its first ".". The rule needs no Unicode table, so it gives the same result everywhere.
func IsEntryName(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if !portableComponent(part) {
			return false
		}
	}
	return true
}

// fileAndDirectory returns a name that, after ASCII case folding, is also a parent directory of
// another name.
func fileAndDirectory(names []string) (string, bool) {
	folded := map[string]bool{}
	for _, name := range names {
		folded[FoldASCII(name)] = true
	}
	for _, name := range names {
		parts := strings.Split(FoldASCII(name), "/")
		for depth := 1; depth < len(parts); depth++ {
			parent := strings.Join(parts[:depth], "/")
			if folded[parent] {
				return parent, true
			}
		}
	}
	return "", false
}

const (
	localSignature       = 0x04034b50
	centralSignature     = 0x02014b50
	endSignature         = 0x06054b50
	zip64LocatorSig      = 0x07064b50
	localSize            = 30
	centralSize          = 46
	endSize              = 22
	maxComment           = 0xffff
	maxExtractVersion    = 63
	profileVersion       = 20
	profileMadeBy        = 3<<8 | profileVersion
	profileDOSDate       = 1<<5 | 1
	profileExternal      = uint32(0o100644) << 16
	saturated32          = 0xffffffff
	maxEndRecordEntries  = 0xffff
	maxEndRecordDistance = 0xffffffff
)

func u16(data []byte, offset int64) uint64 {
	return uint64(binary.LittleEndian.Uint16(data[offset:]))
}

func u32(data []byte, offset int64) uint64 {
	return uint64(binary.LittleEndian.Uint32(data[offset:]))
}

func signatureAt(data []byte, offset int64, signature uint64) bool {
	return offset >= 0 && offset+4 <= int64(len(data)) && u32(data, offset) == signature
}

func departure(message string) *ArchiveError {
	return &ArchiveError{Message: "archive is not in its ecl.zip.store.v1 encoding: " + message}
}

type directoryEntry struct {
	nameBytes      []byte
	madeBy         uint64
	extractVersion uint64
	flags          uint64
	method         uint64
	time           uint64
	date           uint64
	crc            uint64
	compressedSize uint64
	fileSize       uint64
	extraLength    int
	commentLength  int
	disk           uint64
	internal       uint64
	external       uint64
	headerOffset   int64
}

func minimum(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// endRecord locates the end record as a ZIP reader does: the last 22 bytes when they hold one with
// no comment, otherwise the last signature in the range a comment can occupy.
func endRecord(data []byte) (position int64, directorySize, directoryOffset uint64, comment []byte, err error) {
	length := int64(len(data))
	if length < endSize {
		return 0, 0, 0, nil, departure("no end of central directory record")
	}
	position = -1
	if signatureAt(data, length-endSize, endSignature) && u16(data, length-2) == 0 {
		position = length - endSize
	} else {
		start := length - maxComment - endSize
		if start < 0 {
			start = 0
		}
		for offset := length - 4; offset >= start; offset-- {
			if signatureAt(data, offset, endSignature) {
				position = offset
				break
			}
		}
		if position < 0 || position+endSize > length {
			return 0, 0, 0, nil, departure("no end of central directory record")
		}
		comment = data[position+endSize : minimum(length, position+endSize+int64(u16(data, position+20)))]
	}
	if signatureAt(data, position-20, zip64LocatorSig) {
		return 0, 0, 0, nil, departure("a ZIP64 record")
	}
	return position, u32(data, position+12), u32(data, position+16), comment, nil
}

// directory reads the central directory entries as a ZIP reader reads them. Every entry is read
// and its structure checked, but only the first keep are kept, so an archive that holds more
// members than the member limit costs no more memory than the limit (IE1-029); count is the
// number of entries the directory holds.
func directory(data []byte, keep int64) (entries []directoryEntry, count int64, err error) {
	position, size, offset, comment, err := endRecord(data)
	if err != nil {
		return nil, 0, err
	}
	concat := position - int64(size) - int64(offset)
	start := int64(offset) + concat
	if start < 0 {
		return nil, 0, departure("the central directory has a negative offset")
	}
	if len(comment) > 0 {
		return nil, 0, departure("an archive comment")
	}
	stop := start + int64(size)
	entries = []directoryEntry{}
	at := start
	var total uint64
	for total < size {
		if at+centralSize > stop || u32(data, at) != centralSignature {
			return nil, 0, departure("a truncated or unreadable central directory entry")
		}
		nameLength := int64(u16(data, at+28))
		extraLength := int64(u16(data, at+30))
		commentLength := int64(u16(data, at+32))
		flags := u16(data, at+8)
		nameStart := at + centralSize
		nameEnd := minimum(stop, nameStart+nameLength)
		nameBytes := data[nameStart:nameEnd]
		if flags&0x800 != 0 && !utf8.Valid(nameBytes) {
			return nil, 0, departure("a name flagged as UTF-8 that is not UTF-8")
		}
		extraEnd := minimum(stop, nameEnd+extraLength)
		extra := data[nameEnd:extraEnd]
		commentEnd := minimum(stop, extraEnd+commentLength)
		extractVersion := uint64(data[at+6])
		if extractVersion > maxExtractVersion {
			return nil, 0, departure("an unsupported extraction version")
		}
		compressedSize := u32(data, at+20)
		fileSize := u32(data, at+24)
		headerOffset := u32(data, at+42)
		// The extra fields' structure, and the sizes a ZIP64 field gives where a size is saturated.
		for field := 0; len(extra)-field >= 4; {
			kind := binary.LittleEndian.Uint16(extra[field:])
			length := int(binary.LittleEndian.Uint16(extra[field+2:]))
			if length+4 > len(extra)-field {
				return nil, 0, departure("a corrupt extra field")
			}
			if kind == 0x0001 {
				value := extra[field+4 : field+4+length]
				next := func() (uint64, error) {
					if len(value) < 8 {
						return 0, departure("a corrupt ZIP64 extra field")
					}
					read := binary.LittleEndian.Uint64(value)
					value = value[8:]
					return read, nil
				}
				var err error
				if fileSize == saturated32 {
					if fileSize, err = next(); err != nil {
						return nil, 0, err
					}
				}
				if compressedSize == saturated32 {
					if compressedSize, err = next(); err != nil {
						return nil, 0, err
					}
				}
				if headerOffset == saturated32 {
					if headerOffset, err = next(); err != nil {
						return nil, 0, err
					}
				}
			}
			field += length + 4
		}
		if headerOffset > 1<<62 {
			// Beyond any archive: its local header cannot be read, which the member checks find.
			headerOffset = 1 << 62
		}
		count++
		if count > keep {
			total += uint64(centralSize + nameLength + extraLength + commentLength)
			at = commentEnd
			continue
		}
		entries = append(entries, directoryEntry{
			nameBytes: nameBytes, madeBy: u16(data, at+4), extractVersion: extractVersion, flags: flags,
			method: u16(data, at+10), time: u16(data, at+12), date: u16(data, at+14), crc: u32(data, at+16),
			compressedSize: compressedSize, fileSize: fileSize, extraLength: len(extra),
			commentLength: int(commentEnd - extraEnd), disk: u16(data, at+34), internal: u16(data, at+36),
			external: u32(data, at+38), headerOffset: int64(headerOffset) + concat,
		})
		total += uint64(centralSize + nameLength + extraLength + commentLength)
		at = commentEnd
	}
	return entries, count, nil
}

type layoutMember struct {
	nameBytes []byte
	crc       uint32
	size      uint32
}

func appendLocal(out []byte, member layoutMember) []byte {
	out = binary.LittleEndian.AppendUint32(out, localSignature)
	out = binary.LittleEndian.AppendUint16(out, profileVersion)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, profileDOSDate)
	out = binary.LittleEndian.AppendUint32(out, member.crc)
	out = binary.LittleEndian.AppendUint32(out, member.size)
	out = binary.LittleEndian.AppendUint32(out, member.size)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(member.nameBytes)))
	out = binary.LittleEndian.AppendUint16(out, 0)
	return append(out, member.nameBytes...)
}

func appendCentral(out []byte, member layoutMember, offset uint32) []byte {
	out = binary.LittleEndian.AppendUint32(out, centralSignature)
	out = binary.LittleEndian.AppendUint16(out, profileMadeBy)
	out = binary.LittleEndian.AppendUint16(out, profileVersion)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, profileDOSDate)
	out = binary.LittleEndian.AppendUint32(out, member.crc)
	out = binary.LittleEndian.AppendUint32(out, member.size)
	out = binary.LittleEndian.AppendUint32(out, member.size)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(member.nameBytes)))
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint32(out, profileExternal)
	out = binary.LittleEndian.AppendUint32(out, offset)
	return append(out, member.nameBytes...)
}

func appendEnd(out []byte, count int, directoryLength, directoryOffset uint32) []byte {
	out = binary.LittleEndian.AppendUint32(out, endSignature)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, uint16(count))
	out = binary.LittleEndian.AppendUint16(out, uint16(count))
	out = binary.LittleEndian.AppendUint32(out, directoryLength)
	out = binary.LittleEndian.AppendUint32(out, directoryOffset)
	return binary.LittleEndian.AppendUint16(out, 0)
}

// layoutProblem says why data departs from the exact profile encoding of members, or "".
func layoutProblem(data []byte, members []layoutMember) string {
	if len(members) > maxEndRecordEntries {
		return "more members than the end record can count"
	}
	var central []byte
	var offset uint64
	for _, member := range members {
		local := appendLocal(nil, member)
		if offset > maxEndRecordDistance || offset+uint64(len(local)) > uint64(len(data)) || !bytes.Equal(data[offset:offset+uint64(len(local))], local) {
			return "a local header is not at its profile offset or not in profile form"
		}
		central = appendCentral(central, member, uint32(offset))
		offset += uint64(len(local)) + uint64(member.size)
	}
	if offset > maxEndRecordDistance || uint64(len(central)) > maxEndRecordDistance {
		return "the archive is too large for the end record"
	}
	tail := appendEnd(append([]byte{}, central...), len(members), uint32(len(central)), uint32(offset))
	if offset+uint64(len(tail)) != uint64(len(data)) || !bytes.Equal(data[offset:], tail) {
		return "the central directory and end record are not the profile encoding, or bytes follow"
	}
	return ""
}

// ratioExceeded reports whether size > max(stored, 1) * ratio, without overflow.
func ratioExceeded(size, stored uint64, ratio int64) bool {
	if stored < 1 {
		stored = 1
	}
	high, low := bits.Mul64(stored, uint64(ratio))
	return high == 0 && size > low
}

// ReadArchive returns the members of an archive in exact ecl.zip.store.v1 form (INTEGRITY-ENVELOPE-1
// section 8, IE1-028 to IE1-031), in archive order, without decompressing anything. Anything else
// is an *ArchiveError, whose Limit is true when the archive exceeds one of limits. The checks run
// in the order of the reference (ecl_reference.offline.verify_zip_members): the archive's bytes;
// the end record and central directory, read as a ZIP reader reads them, and the archive comment;
// the member count, then member by member the encryption flag, the declared size, the running
// total and the declared compression ratio; then member by member a NUL in the name, the name's
// stored bytes, the entry name rule, aliases, the fixed metadata and encoding, the order of names,
// the local header and the CRC-32 of the data; names that are also parent directories; and the
// exact encoding of the whole archive. Invalid limits are ErrInvalidLimits.
func ReadArchive(data []byte, limits Limits) ([]Member, error) {
	if err := limits.check(); err != nil {
		return nil, err
	}
	if int64(len(data)) > limits.MaxArchiveBytes {
		return nil, &ArchiveError{Message: "archive size exceeds the verifier budget", Limit: true}
	}
	entries, count, err := directory(data, limits.MaxMemberCount)
	if err != nil {
		return nil, err
	}
	if count > limits.MaxMemberCount {
		return nil, &ArchiveError{Message: "archive member count exceeds the verifier budget", Limit: true}
	}
	var total uint64
	for _, entry := range entries {
		if entry.flags&0x1 != 0 {
			return nil, departure("an encrypted member: " + string(entry.nameBytes))
		}
		if entry.fileSize > uint64(limits.MaxEntryUncompressedBytes) {
			return nil, &ArchiveError{Message: "archive member exceeds the verifier budget: " + string(entry.nameBytes), Limit: true}
		}
		total += entry.fileSize
		if total > uint64(limits.MaxTotalUncompressedBytes) {
			return nil, &ArchiveError{Message: "archive expansion exceeds the verifier budget", Limit: true}
		}
		if entry.fileSize > 0 && ratioExceeded(entry.fileSize, entry.compressedSize, limits.MaxCompressionRatio) {
			return nil, &ArchiveError{Message: "archive member compression ratio exceeds the verifier budget: " + string(entry.nameBytes), Limit: true}
		}
	}
	seen := map[string]bool{}
	layout := []layoutMember{}
	members := []Member{}
	var prior []byte
	length := int64(len(data))
	for _, entry := range entries {
		name := string(entry.nameBytes)
		if bytes.IndexByte(entry.nameBytes, 0) >= 0 {
			return nil, departure(fmt.Sprintf("a name with a NUL character: %q", name))
		}
		if int64(len(entry.nameBytes)) > limits.MaxPathBytes {
			return nil, &ArchiveError{Message: "archive member name exceeds the verifier budget", Limit: true}
		}
		if !IsEntryName(name) {
			return nil, departure(fmt.Sprintf("a name that is not an entry name: %q", name))
		}
		alias := FoldASCII(name)
		if seen[alias] {
			return nil, departure("a duplicate member: " + name)
		}
		seen[alias] = true
		if entry.external != uint64(profileExternal) || entry.madeBy != profileMadeBy || entry.extractVersion != profileVersion ||
			entry.disk != 0 || entry.internal != 0 || entry.date != profileDOSDate || entry.time != 0 || entry.method != 0 ||
			entry.flags != 0 || entry.extraLength != 0 || entry.commentLength != 0 {
			return nil, departure("member metadata or encoding outside the profile: " + name)
		}
		if prior != nil && bytes.Compare(entry.nameBytes, prior) < 0 {
			return nil, departure("entries are not in the bytewise order of their names")
		}
		prior = entry.nameBytes
		local := entry.headerOffset
		if local < 0 || local+localSize > length || u32(data, local) != localSignature {
			return nil, departure("an unreadable local header: " + name)
		}
		localNameLength := int64(u16(data, local+26))
		localName := data[local+localSize : minimum(length, local+localSize+localNameLength)]
		if !bytes.Equal(localName, entry.nameBytes) {
			return nil, departure("the local and central names differ: " + name)
		}
		start := local + localSize + localNameLength + int64(u16(data, local+28))
		size := entry.compressedSize
		if entry.fileSize < size {
			size = entry.fileSize
		}
		content := []byte{}
		if size > 0 {
			if start+int64(size) > length {
				return nil, departure("the data of a member is truncated: " + name)
			}
			content = data[start : start+int64(size)]
		}
		if uint64(crc32.ChecksumIEEE(content)) != entry.crc || entry.compressedSize < entry.fileSize {
			return nil, departure("the CRC-32 or size of a member does not hold: " + name)
		}
		layout = append(layout, layoutMember{nameBytes: entry.nameBytes, crc: uint32(entry.crc), size: uint32(entry.fileSize)})
		members = append(members, Member{Name: name, Data: content})
	}
	names := make([]string, len(members))
	for index, member := range members {
		names[index] = member.Name
	}
	if conflict, found := fileAndDirectory(names); found {
		return nil, departure("a member is both a file and a directory: " + conflict)
	}
	if problem := layoutProblem(data, layout); problem != "" {
		return nil, departure(problem)
	}
	return members, nil
}
