package offline

import (
	"errors"
	"testing"
)

func TestArchiveByteCeilingPrecedesInputClassification(t *testing.T) {
	for _, maximum := range []int64{2_147_483_648, 9_007_199_254_740_991} {
		limits := DefaultLimits
		limits.MaxArchiveBytes = maximum
		for _, input := range [][]byte{nil, []byte("not a zip")} {
			if _, err := ReadArchive(input, limits); !errors.Is(err, ErrInvalidLimits) {
				t.Errorf("maximum %d classified input before rejecting configuration: %v", maximum, err)
			}
		}
	}
}

func TestArchiveByteCeilingItselfIsValid(t *testing.T) {
	limits := DefaultLimits
	limits.MaxArchiveBytes = 2_147_483_647
	empty := make([]byte, 22)
	copy(empty, []byte{'P', 'K', 5, 6})
	if members, err := ReadArchive(empty, limits); err != nil || len(members) != 0 {
		t.Fatalf("ceiling refused a valid empty archive: %v", err)
	}
}
