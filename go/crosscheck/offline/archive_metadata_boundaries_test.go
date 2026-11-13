package offline

// Stored metadata and declared budgets. Robert F. Tilley Jr.; G-14, Inc.
import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"reflect"
	"sort"
	"testing"
)

func TestArchiveMetadataBoundaries(t *testing.T) {
	var doc struct {
		Cases []struct {
			ID      string           `json:"id"`
			Archive string           `json:"archive_base64"`
			Limits  map[string]int64 `json:"limits"`
			Reader  string           `json:"reader_code"`
			Verdict string           `json:"package_verdict"`
			Codes   []string         `json:"package_codes"`
		}
	}
	if err := json.Unmarshal(repository(t, "tests/fixtures/archive-metadata-boundaries.json"), &doc); err != nil {
		t.Fatal(err)
	}
	trustPolicy := policy(t, suite+"/trust-policy.json")
	for _, row := range doc.Cases {
		t.Run(row.ID, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(row.Archive)
			if err != nil {
				t.Fatal(err)
			}
			l := row.Limits
			limits := Limits{MaxArchiveBytes: l["max_archive_bytes"], MaxMemberCount: l["max_member_count"], MaxEntryUncompressedBytes: l["max_entry_uncompressed_bytes"], MaxTotalUncompressedBytes: l["max_total_uncompressed_bytes"], MaxCompressionRatio: l["max_compression_ratio"], MaxPathBytes: l["max_path_bytes"]}
			code := "accepted"
			_, err = ReadArchive(data, limits)
			if err != nil {
				var refusal *ArchiveError
				if !errors.As(err, &refusal) {
					t.Fatal(err)
				}
				code = "ecl.error.semantic-invalid.v1"
				if refusal.Limit {
					code = "ecl.error.resource-limit-exceeded.v1"
				}
			}
			if code != row.Reader {
				t.Fatalf("reader %s, want %s", code, row.Reader)
			}
			report, err := Verify(data, trustPolicy, Options{Options: evidence.Options{Now: now}, Limits: &limits})
			if err != nil {
				t.Fatal(err)
			}
			codes := Identifiers(report)
			sort.Strings(codes)
			if report.Verdict != row.Verdict || !reflect.DeepEqual(codes, row.Codes) {
				t.Fatalf("package %s %v, want %s %v", report.Verdict, codes, row.Verdict, row.Codes)
			}
		})
	}
}
