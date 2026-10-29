package offline

import (
	"fmt"
	"hash/crc32"
	"sort"
)

// WriteArchive returns the ecl.zip.store.v1 archive of members, sorted by the bytes of their names:
// what a producer of the profile writes (IE1-031). Every name must be an entry name.
func WriteArchive(members []Member) ([]byte, error) {
	sorted := append([]Member{}, members...)
	for _, member := range sorted {
		if !IsEntryName(member.Name) {
			return nil, fmt.Errorf("not an ecl.zip.store.v1 entry name: %q", member.Name)
		}
		if uint64(len(member.Data)) > saturated32 {
			return nil, fmt.Errorf("member too large for the profile: %s", member.Name)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var out, central []byte
	for _, member := range sorted {
		entry := layoutMember{nameBytes: []byte(member.Name), crc: crc32.ChecksumIEEE(member.Data), size: uint32(len(member.Data))}
		offset := uint32(len(out))
		out = append(appendLocal(out, entry), member.Data...)
		central = appendCentral(central, entry, offset)
	}
	directoryOffset := uint32(len(out))
	out = append(out, central...)
	return appendEnd(out, len(sorted), uint32(len(central)), directoryOffset), nil
}
