// Command ecl-corpus-check evaluates the shared conformance corpus with this module and writes a
// cross-implementation report with raw evidence:
//
//	ecl-corpus-check --repo-root DIR --report FILE --revision COMMIT
//
// DIR is the root of the ECL-1 package, FILE a report file that does not exist yet and COMMIT the
// 40-character revision of the source that the report names. The summary goes to standard output;
// the exit status is 0 when every vector meets its expectation, 1 when one does not and 2 when the
// corpus cannot be evaluated.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/corpus"
)

func main() {
	root := flag.String("repo-root", "", "ECL repository root")
	report := flag.String("report", "", "fresh report output path")
	revision := flag.String("revision", "", "source revision (40 lowercase hexadecimal characters)")
	flag.Parse()
	if *root == "" || *report == "" || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(*revision) {
		fmt.Fprintln(os.Stderr, "repo-root, report and a source revision are required")
		os.Exit(2)
	}
	summary, met, err := corpus.Run(*root, *revision, *report)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !met {
		os.Exit(1)
	}
}
