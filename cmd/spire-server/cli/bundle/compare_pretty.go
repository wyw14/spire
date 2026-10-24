package bundle

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spiffe/spire/pkg/common/bundleutil"
)

// writePrettyDiff writes a deterministic, human-readable description of the
// bundle diff. Every list in the diff is already sorted by a stable key, so
// the output does not depend on the entry order of the source bundles.
func writePrettyDiff(out io.Writer, d *bundleutil.Diff) error {
	var b strings.Builder

	trustDomain := d.TrustDomain
	if trustDomain == "" {
		trustDomain = "unspecified"
	}
	fmt.Fprintf(&b, "Trust domain: %s\n", trustDomain)

	writeX509Section(&b, d.X509Authorities)
	writeKeySection(&b, "JWT authorities", d.JWTAuthorities)
	writeKeySection(&b, "WIT authorities", d.WITAuthorities)
	writeMetadataSection(&b, d)

	if !d.HasDifferences() {
		b.WriteString("No differences found; the bundles are semantically identical (entry order and JSON formatting ignored).\n")
	}

	_, err := io.WriteString(out, b.String())
	return err
}

func writeX509Section(b *strings.Builder, diff bundleutil.X509Diff) {
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		b.WriteString("X.509 authorities: no differences\n")
		return
	}

	fmt.Fprintf(b, "X.509 authorities: %s\n", changeCount(len(diff.Added), "added", len(diff.Removed), "removed", 0, "changed"))
	writeX509List(b, "Added", diff.Added)
	writeX509List(b, "Removed", diff.Removed)
}

func writeKeySection(b *strings.Builder, title string, diff bundleutil.KeySetDiff) {
	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0 {
		fmt.Fprintf(b, "%s: no differences\n", title)
		return
	}

	fmt.Fprintf(b, "%s: %s\n", title, changeCount(len(diff.Added), "added", len(diff.Removed), "removed", len(diff.Changed), "changed"))
	writeKeyList(b, "Added", diff.Added)
	writeKeyList(b, "Removed", diff.Removed)
	writeKeyChangeList(b, "Changed", diff.Changed)
}

func writeMetadataSection(b *strings.Builder, d *bundleutil.Diff) {
	if d.SequenceNumber == nil && d.RefreshHint == nil {
		b.WriteString("Metadata: no differences\n")
		return
	}

	b.WriteString("Metadata:\n")
	if d.SequenceNumber != nil {
		fmt.Fprintf(b, "  Sequence number: %s -> %s\n",
			numberOrUnset(d.SequenceNumber.Before), numberOrUnset(d.SequenceNumber.After))
	}
	if d.RefreshHint != nil {
		fmt.Fprintf(b, "  Refresh hint: %s -> %s\n",
			durationOrUnset(d.RefreshHint.BeforeSeconds), durationOrUnset(d.RefreshHint.AfterSeconds))
	}
}

func writeX509List(b *strings.Builder, heading string, authorities []bundleutil.X509Authority) {
	if len(authorities) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", heading)
	for _, authority := range authorities {
		fmt.Fprintf(b, "    - Subject: %s\n", oneLine(authority.Subject))
		fmt.Fprintf(b, "      Issuer: %s\n", oneLine(authority.Issuer))
		fmt.Fprintf(b, "      Serial number: %s\n", authority.SerialNumber)
		fmt.Fprintf(b, "      Not after: %s\n", authority.NotAfter.Format(time.RFC3339))
		fmt.Fprintf(b, "      SHA-256 fingerprint: %s\n", authority.SHA256Fingerprint)
	}
}

func writeKeyList(b *strings.Builder, heading string, keys []bundleutil.KeyInfo) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", heading)
	for _, key := range keys {
		fmt.Fprintf(b, "    - Key ID: %q (%s), SHA-256 fingerprint: %s\n",
			key.KeyID, key.KeyType, key.SHA256Fingerprint)
	}
}

func writeKeyChangeList(b *strings.Builder, heading string, keys []bundleutil.KeyChange) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", heading)
	for _, key := range keys {
		fmt.Fprintf(b, "    - Key ID: %q (%s)\n", key.KeyID, changeKeyType(key))
		fmt.Fprintf(b, "      Before SHA-256 fingerprint: %s\n", key.Before.SHA256Fingerprint)
		fmt.Fprintf(b, "      After SHA-256 fingerprint: %s\n", key.After.SHA256Fingerprint)
	}
}

func changeKeyType(change bundleutil.KeyChange) string {
	if change.Before.KeyType == change.After.KeyType {
		return change.Before.KeyType
	}
	return change.Before.KeyType + " -> " + change.After.KeyType
}

func changeCount(first int, firstLabel string, second int, secondLabel string, third int, thirdLabel string) string {
	var parts []string
	if first > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", first, plural(firstLabel, first)))
	}
	if second > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", second, plural(secondLabel, second)))
	}
	if third > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", third, plural(thirdLabel, third)))
	}
	return strings.Join(parts, ", ")
}

func plural(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func numberOrUnset(value *uint64) string {
	if value == nil {
		return "unset"
	}
	return fmt.Sprintf("%d", *value)
}

func durationOrUnset(seconds *int64) string {
	if seconds == nil {
		return "unset"
	}
	return fmt.Sprintf("%ds", *seconds)
}

// oneLine collapses newlines in certificate names so each field stays on a
// single output line.
func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
