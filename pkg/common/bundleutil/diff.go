package bundleutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
)

// Exit codes reported by the offline bundle comparison command.
const (
	// CompareExitCodeIdentical indicates that the bundles are semantically
	// identical.
	CompareExitCodeIdentical = 0
	// CompareExitCodeInvalid indicates that the input could not be parsed or
	// the bundles are not comparable (e.g. different trust domains).
	CompareExitCodeInvalid = 1
	// CompareExitCodeDifferent indicates that semantic differences were found.
	CompareExitCodeDifferent = 2
)

// ErrDifferentTrustDomains is returned by Compare when the two bundles belong
// to different trust domains.
var ErrDifferentTrustDomains = errors.New("cannot compare bundles for different trust domains")

// Diff describes the semantic differences between two SPIFFE bundles. All
// slices are sorted by stable keys (fingerprint or key ID), so marshalling a
// Diff produces deterministic output regardless of the ordering in the source
// documents.
type Diff struct {
	// TrustDomain is the trust domain that both bundles belong to. It is empty
	// when the trust domain was not conveyed with the bundles.
	TrustDomain string `json:"trust_domain"`

	// X509Authorities reports added and removed X.509 CA certificates.
	// Certificates are identified by their full contents, so a certificate
	// whose contents changed is reported as removed and added.
	X509Authorities X509Diff `json:"x509_authorities"`

	// JWTAuthorities reports added, removed, and changed JWT verification keys.
	JWTAuthorities KeySetDiff `json:"jwt_authorities"`

	// WITAuthorities reports added, removed, and changed WIT verification keys.
	WITAuthorities KeySetDiff `json:"wit_authorities"`

	// SequenceNumber is set when the sequence numbers differ. It is reported
	// separately because it is metadata and not trust material.
	SequenceNumber *NumberDiff `json:"sequence_number,omitempty"`

	// RefreshHint is set when the refresh hints differ. It is reported
	// separately because it is metadata and not trust material.
	RefreshHint *DurationDiff `json:"refresh_hint,omitempty"`
}

// X509Diff reports X.509 authority differences.
type X509Diff struct {
	Added   []X509Authority `json:"added"`
	Removed []X509Authority `json:"removed"`
}

// KeySetDiff reports verification key differences for a single use (JWT-SVID
// or WIT-SVID). Keys are identified by their key ID; a key ID present in both
// bundles with different public key material is reported as a change.
type KeySetDiff struct {
	Added   []KeyInfo   `json:"added"`
	Removed []KeyInfo   `json:"removed"`
	Changed []KeyChange `json:"changed"`
}

// X509Authority describes a single X.509 CA certificate. The SHA-256
// fingerprint is computed over the full DER-encoded certificate, which is the
// identity used by the comparison.
type X509Authority struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	SerialNumber      string    `json:"serial_number"`
	NotAfter          time.Time `json:"not_after"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
}

// KeyInfo describes a single JWT or WIT verification public key.
type KeyInfo struct {
	KeyID             string `json:"key_id"`
	KeyType           string `json:"key_type"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
}

// KeyChange describes a key ID that is present in both bundles but backed by
// different public key material.
type KeyChange struct {
	KeyID  string  `json:"key_id"`
	Before KeyInfo `json:"before"`
	After  KeyInfo `json:"after"`
}

// NumberDiff describes a change of an optional numeric metadata value. A nil
// value means the metadata was not set in the corresponding bundle.
type NumberDiff struct {
	Before *uint64 `json:"before"`
	After  *uint64 `json:"after"`
}

// DurationDiff describes a change of an optional duration metadata value,
// expressed in seconds. A nil value means the metadata was not set in the
// corresponding bundle.
type DurationDiff struct {
	BeforeSeconds *int64 `json:"before_seconds"`
	AfterSeconds  *int64 `json:"after_seconds"`
}

// HasDifferences reports whether the two compared bundles differ in any way,
// including sequence number or refresh hint metadata.
func (d *Diff) HasDifferences() bool {
	return len(d.X509Authorities.Added) != 0 ||
		len(d.X509Authorities.Removed) != 0 ||
		len(d.JWTAuthorities.Added) != 0 ||
		len(d.JWTAuthorities.Removed) != 0 ||
		len(d.JWTAuthorities.Changed) != 0 ||
		len(d.WITAuthorities.Added) != 0 ||
		len(d.WITAuthorities.Removed) != 0 ||
		len(d.WITAuthorities.Changed) != 0 ||
		d.SequenceNumber != nil ||
		d.RefreshHint != nil
}

// Compare semantically compares two SPIFFE bundles. The bundles are not
// modified or merged. Bundle contents are treated as sets, so key order and
// JSON formatting are ignored. An error is returned when the bundles belong to
// different trust domains.
func Compare(a, b *spiffebundle.Bundle) (*Diff, error) {
	if a == nil {
		return nil, errors.New("first bundle is nil")
	}
	if b == nil {
		return nil, errors.New("second bundle is nil")
	}
	if a.TrustDomain() != b.TrustDomain() {
		return nil, fmt.Errorf("%w: %q vs %q", ErrDifferentTrustDomains,
			a.TrustDomain().Name(), b.TrustDomain().Name())
	}

	diff := &Diff{
		TrustDomain:     a.TrustDomain().Name(),
		X509Authorities: compareX509Authorities(a.X509Authorities(), b.X509Authorities()),
	}

	jwtAuthorities, err := compareKeySet(a.JWTAuthorities(), b.JWTAuthorities())
	if err != nil {
		return nil, err
	}
	diff.JWTAuthorities = jwtAuthorities

	witAuthorities, err := compareKeySet(a.WITAuthorities(), b.WITAuthorities())
	if err != nil {
		return nil, err
	}
	diff.WITAuthorities = witAuthorities

	if before, after, ok := optionalUint64Changed(
		numberFromBundle(a.SequenceNumber()),
		numberFromBundle(b.SequenceNumber()),
	); ok {
		diff.SequenceNumber = &NumberDiff{Before: before, After: after}
	}

	if before, after, ok := optionalInt64Changed(
		durationSecondsFromBundle(a.RefreshHint()),
		durationSecondsFromBundle(b.RefreshHint()),
	); ok {
		diff.RefreshHint = &DurationDiff{BeforeSeconds: before, AfterSeconds: after}
	}

	return diff, nil
}

func compareX509Authorities(a, b []*x509.Certificate) X509Diff {
	aByFingerprint := make(map[string]*x509.Certificate, len(a))
	bByFingerprint := make(map[string]*x509.Certificate, len(b))
	for _, cert := range a {
		aByFingerprint[x509Fingerprint(cert)] = cert
	}
	for _, cert := range b {
		bByFingerprint[x509Fingerprint(cert)] = cert
	}

	diff := X509Diff{
		Added:   make([]X509Authority, 0),
		Removed: make([]X509Authority, 0),
	}
	for fingerprint, cert := range bByFingerprint {
		if _, ok := aByFingerprint[fingerprint]; !ok {
			diff.Added = append(diff.Added, describeX509Authority(cert))
		}
	}
	for fingerprint, cert := range aByFingerprint {
		if _, ok := bByFingerprint[fingerprint]; !ok {
			diff.Removed = append(diff.Removed, describeX509Authority(cert))
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return diff.Added[i].SHA256Fingerprint < diff.Added[j].SHA256Fingerprint
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return diff.Removed[i].SHA256Fingerprint < diff.Removed[j].SHA256Fingerprint
	})
	return diff
}

func compareKeySet(a, b map[string]crypto.PublicKey) (KeySetDiff, error) {
	diff := KeySetDiff{
		Added:   make([]KeyInfo, 0),
		Removed: make([]KeyInfo, 0),
		Changed: make([]KeyChange, 0),
	}

	for keyID, key := range b {
		if _, ok := a[keyID]; !ok {
			info, err := describeKey(keyID, key)
			if err != nil {
				return KeySetDiff{}, err
			}
			diff.Added = append(diff.Added, info)
		}
	}
	for keyID, key := range a {
		if _, ok := b[keyID]; !ok {
			info, err := describeKey(keyID, key)
			if err != nil {
				return KeySetDiff{}, err
			}
			diff.Removed = append(diff.Removed, info)
		}
	}
	for keyID, before := range a {
		after, ok := b[keyID]
		if !ok {
			continue
		}
		equal, err := publicKeysEqual(before, after)
		if err != nil {
			return KeySetDiff{}, err
		}
		if !equal {
			beforeInfo, err := describeKey(keyID, before)
			if err != nil {
				return KeySetDiff{}, err
			}
			afterInfo, err := describeKey(keyID, after)
			if err != nil {
				return KeySetDiff{}, err
			}
			diff.Changed = append(diff.Changed, KeyChange{
				KeyID:  keyID,
				Before: beforeInfo,
				After:  afterInfo,
			})
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return diff.Added[i].KeyID < diff.Added[j].KeyID
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return diff.Removed[i].KeyID < diff.Removed[j].KeyID
	})
	sort.Slice(diff.Changed, func(i, j int) bool {
		return diff.Changed[i].KeyID < diff.Changed[j].KeyID
	})
	return diff, nil
}

func describeX509Authority(cert *x509.Certificate) X509Authority {
	return X509Authority{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      strings.ToUpper(cert.SerialNumber.Text(16)),
		NotAfter:          cert.NotAfter.UTC(),
		SHA256Fingerprint: x509Fingerprint(cert),
	}
}

func describeKey(keyID string, key crypto.PublicKey) (KeyInfo, error) {
	fingerprint, err := publicKeyFingerprint(key)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		KeyID:             keyID,
		KeyType:           keyType(key),
		SHA256Fingerprint: fingerprint,
	}, nil
}

func keyType(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "EC-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", key)
	}
}

func publicKeysEqual(a, b crypto.PublicKey) (bool, error) {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, fmt.Errorf("failed to marshal public key: %w", err)
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return bytes.Equal(aBytes, bBytes), nil
}

func publicKeyFingerprint(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func x509Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func numberFromBundle(value uint64, ok bool) *uint64 {
	if !ok {
		return nil
	}
	v := value
	return &v
}

func durationSecondsFromBundle(value time.Duration, ok bool) *int64 {
	if !ok {
		return nil
	}
	v := int64(value / time.Second)
	return &v
}

// A nil pointer means the corresponding metadata was not present in the
// bundle, so both presence and value are compared.
func optionalUint64Changed(before, after *uint64) (*uint64, *uint64, bool) {
	switch {
	case before == nil && after == nil:
		return nil, nil, false
	case before == nil || after == nil:
		return before, after, true
	case *before != *after:
		return before, after, true
	default:
		return nil, nil, false
	}
}

func optionalInt64Changed(before, after *int64) (*int64, *int64, bool) {
	switch {
	case before == nil && after == nil:
		return nil, nil, false
	case before == nil || after == nil:
		return before, after, true
	case *before != *after:
		return before, after, true
	default:
		return nil, nil, false
	}
}
