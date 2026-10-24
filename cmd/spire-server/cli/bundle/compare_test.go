package bundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestCompare(t *testing.T) {
	suite.Run(t, new(CompareSuite))
}

type CompareSuite struct {
	suite.Suite

	dir string

	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command

	fixture fixture
}

func (s *CompareSuite) SetupTest() {
	s.dir = s.T().TempDir()
	s.stdin = new(bytes.Buffer)
	s.stdout = new(bytes.Buffer)
	s.stderr = new(bytes.Buffer)
	s.fixture = newFixture(s.T())

	s.cmd = newCompareCommand(&common_cli.Env{
		Stdin:  s.stdin,
		Stdout: s.stdout,
		Stderr: s.stderr,
	})
}

func (s *CompareSuite) TestSynopsis() {
	s.Contains(s.cmd.Synopsis(), "SPIFFE-format trust bundle")
}

func (s *CompareSuite) TestHelp() {
	s.Equal("flag: help requested", s.cmd.Help())
	s.Contains(s.stderr.String(), "Usage: bundle compare")
	s.Contains(s.stderr.String(), "-first")
	s.Contains(s.stderr.String(), "-second")
	s.Contains(s.stderr.String(), "Exit status")
}

func (s *CompareSuite) TestHelpIsOffline() {
	s.Equal("flag: help requested", s.cmd.Help())
	// The command must not require server connection flags.
	s.NotContains(s.stderr.String(), "socketPath")
	s.NotContains(s.stderr.String(), "namedPipeName")
}

func (s *CompareSuite) TestBadFlags() {
	code := s.cmd.Run([]string{"-badflag"})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Equal("", s.stdout.String())
	s.Contains(s.stderr.String(), "flag provided but not defined")
}

func (s *CompareSuite) TestMissingPaths() {
	code := s.cmd.Run([]string{"-firstTrustDomain", "example.org"})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Contains(s.stderr.String(), "both -first and -second")
	s.Equal("", s.stdout.String())
}

func (s *CompareSuite) TestUnexpectedPositionalArguments() {
	firstPath, secondPath := s.writeFixtureBundles()
	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath, "extra",
	})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Contains(s.stderr.String(), "unexpected positional arguments")
}

func (s *CompareSuite) TestBothBundlesFromStdinRejected() {
	code := s.cmd.Run([]string{"-first", "-", "-second", "-"})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Contains(s.stderr.String(), "only one of -first or -second")
}

func (s *CompareSuite) TestNonexistentFile() {
	firstPath, _ := s.writeFixtureBundles()
	code := s.cmd.Run([]string{
		"-first", firstPath,
		"-second", filepath.Join(s.dir, "missing.json"),
	})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Contains(s.stderr.String(), "unable to load second bundle")
}

func (s *CompareSuite) TestInvalidInputs() {
	validPath, _ := s.writeFixtureBundles()

	for name, content := range map[string]string{
		"not JSON":            `{not json`,
		"missing keys field":  `{}`,
		"JWT key without kid": `{"keys":[{"use":"jwt-svid","kty":"EC","crv":"P-256","x":"AA","y":"BB"}]}`,
		"x509 key no cert":    `{"keys":[{"use":"x509-svid","kty":"EC","crv":"P-256","x":"AA","y":"BB"}]}`,
	} {
		s.Run(name, func() {
			badPath := filepath.Join(s.dir, "bad-"+name+".json")
			s.Require().NoError(os.WriteFile(badPath, []byte(content), 0o600))

			code := s.cmd.Run([]string{"-first", validPath, "-second", badPath})
			s.Equal(bundleutil.CompareExitCodeInvalid, code)
			s.Contains(s.stderr.String(), "unable to parse second bundle")
			s.Equal("", s.stdout.String())
		})
	}
}

func (s *CompareSuite) TestInvalidTrustDomainName() {
	firstPath, secondPath := s.writeFixtureBundles()
	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "not a domain",
	})
	s.Equal(bundleutil.CompareExitCodeInvalid, code)
	s.Contains(s.stderr.String(), "invalid -firstTrustDomain")
}

func (s *CompareSuite) TestDifferentTrustDomainsRejected() {
	firstPath, secondPath := s.writeFixtureBundles()

	for _, args := range [][]string{
		{"-firstTrustDomain", "a.example", "-secondTrustDomain", "b.example"},
		{"-firstTrustDomain", "spiffe://a.example", "-secondTrustDomain", "spiffe://b.example"},
	} {
		code := s.cmd.Run(append([]string{"-first", firstPath, "-second", secondPath}, args...))
		s.Equal(bundleutil.CompareExitCodeInvalid, code)
		s.Contains(s.stderr.String(), "different trust domains")
		s.Equal("", s.stdout.String(), "no report must be emitted for incomparable bundles")
	}
}

func (s *CompareSuite) TestTrustDomainURIAliases() {
	firstPath, secondPath := s.writeFixtureBundles()
	// Name form and SPIFFE ID form denote the same trust domain.
	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "spiffe://example.org",
		"-secondTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeDifferent, code)
}

func (s *CompareSuite) TestSecondTrustDomainDefaultsToFirst() {
	firstPath, secondPath := s.writeFixtureBundles()
	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeDifferent, code)
	s.Contains(s.stdout.String(), "Trust domain: example.org")
}

func (s *CompareSuite) TestIdenticalBundlesIgnoringOrderAndFormatting() {
	base := s.newBaseBundle()
	firstBytes, err := base.Marshal()
	s.Require().NoError(err)
	firstPath := filepath.Join(s.dir, "first.json")
	s.Require().NoError(os.WriteFile(firstPath, firstBytes, 0o600))

	// Same semantic contents, but with keys in reverse order and indented.
	secondPath := s.writeBytes("second-pretty.json", reorderAndIndent(s.T(), firstBytes))

	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeIdentical, code)
	output := s.stdout.String()
	s.Contains(output, "Trust domain: example.org")
	s.Contains(output, "X.509 authorities: no differences")
	s.Contains(output, "JWT authorities: no differences")
	s.Contains(output, "WIT authorities: no differences")
	s.Contains(output, "Metadata: no differences")
	s.Contains(output, "No differences found")
}

func (s *CompareSuite) TestIdenticalBundlesWithoutTrustDomain() {
	base := s.newBaseBundle()
	firstPath := s.writeBundle("first.json", base)
	secondPath := s.writeBytes("second-pretty.json", reorderAndIndent(s.T(), s.mustMarshal(base)))

	code := s.cmd.Run([]string{"-first", firstPath, "-second", secondPath})
	s.Equal(bundleutil.CompareExitCodeIdentical, code)
	s.Contains(s.stdout.String(), "Trust domain: unspecified")
}

func (s *CompareSuite) TestDifferencesPrettyOutput() {
	firstPath, secondPath := s.writeFixtureBundles()

	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeDifferent, code)

	output := s.stdout.String()
	s.Contains(output, "X.509 authorities: 1 added, 1 removed")
	s.Contains(output, "JWT authorities: 1 added, 1 changed")
	s.Contains(output, "WIT authorities: no differences")
	s.Contains(output, "Key ID: \"rotated\"")
	s.Contains(output, "Before SHA-256 fingerprint:")
	s.Contains(output, "After SHA-256 fingerprint:")
	s.Contains(output, "Sequence number: 1 -> 2")
	s.Contains(output, "Refresh hint: 60s -> 120s")

	// The rotated certificate fingerprints must be reported.
	s.Contains(output, fingerprintHex(s.fixture.oldCert.Raw))
	s.Contains(output, fingerprintHex(s.fixture.newCert.Raw))
}

func (s *CompareSuite) TestJSONOutput() {
	firstPath, secondPath := s.writeFixtureBundles()
	args := []string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "example.org",
		"-output", "json",
	}

	s.Equal(bundleutil.CompareExitCodeDifferent, s.cmd.Run(args))
	firstOutput := s.stdout.String()

	var diff bundleutil.Diff
	s.Require().NoError(json.Unmarshal([]byte(firstOutput), &diff))
	s.Equal("example.org", diff.TrustDomain)
	s.Len(diff.X509Authorities.Added, 1)
	s.Len(diff.X509Authorities.Removed, 1)
	s.Len(diff.JWTAuthorities.Added, 1)
	s.Equal("added", diff.JWTAuthorities.Added[0].KeyID)
	s.Len(diff.JWTAuthorities.Changed, 1)
	s.Equal("rotated", diff.JWTAuthorities.Changed[0].KeyID)
	s.NotEqual(
		diff.JWTAuthorities.Changed[0].Before.SHA256Fingerprint,
		diff.JWTAuthorities.Changed[0].After.SHA256Fingerprint,
	)
	s.Empty(diff.WITAuthorities.Added)
	s.Empty(diff.WITAuthorities.Removed)
	s.Empty(diff.WITAuthorities.Changed)
	s.Require().NotNil(diff.SequenceNumber)
	s.Equal(uint64(1), *diff.SequenceNumber.Before)
	s.Equal(uint64(2), *diff.SequenceNumber.After)
	s.Require().NotNil(diff.RefreshHint)
	s.Equal(int64(60), *diff.RefreshHint.BeforeSeconds)
	s.Equal(int64(120), *diff.RefreshHint.AfterSeconds)

	// JSON output must be stable across invocations.
	s.stdout.Reset()
	s.Equal(bundleutil.CompareExitCodeDifferent, s.cmd.Run(args))
	s.Equal(firstOutput, s.stdout.String())
}

func (s *CompareSuite) TestJSONOutputIdentical() {
	firstPath, _ := s.writeFixtureBundles()
	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", firstPath,
		"-firstTrustDomain", "example.org",
		"-output", "json",
	})
	s.Equal(bundleutil.CompareExitCodeIdentical, code)

	var diff bundleutil.Diff
	s.Require().NoError(json.Unmarshal(s.stdout.Bytes(), &diff))
	s.False(diff.HasDifferences())
	s.Empty(diff.X509Authorities.Added)
	s.Empty(diff.JWTAuthorities.Changed)
	s.Nil(diff.SequenceNumber)
	s.Nil(diff.RefreshHint)
}

func (s *CompareSuite) TestMetadataOnlyDifference() {
	base := s.newBaseBundle()
	other := s.newBaseBundle()
	other.SetSequenceNumber(2)

	firstPath := s.writeBundle("first.json", base)
	secondPath := s.writeBundle("second.json", other)

	code := s.cmd.Run([]string{
		"-first", firstPath, "-second", secondPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeDifferent, code)
	s.Contains(s.stdout.String(), "X.509 authorities: no differences")
	s.Contains(s.stdout.String(), "JWT authorities: no differences")
	s.Contains(s.stdout.String(), "WIT authorities: no differences")
	s.Contains(s.stdout.String(), "Sequence number: 1 -> 2")
}

func (s *CompareSuite) TestFirstBundleFromStdin() {
	base := s.newBaseBundle()
	firstPath := s.writeBundle("first.json", base)

	s.stdin = bytes.NewBuffer(s.mustMarshal(base))
	s.cmd = newCompareCommand(&common_cli.Env{
		Stdin:  s.stdin,
		Stdout: s.stdout,
		Stderr: s.stderr,
	})

	code := s.cmd.Run([]string{
		"-first", "-", "-second", firstPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeIdentical, code)
	s.Contains(s.stdout.String(), "No differences found")
}

func (s *CompareSuite) TestRefreshHintSetAndCleared() {
	base := s.newBaseBundle()
	withoutHint := spiffebundle.New(base.TrustDomain())
	withoutHint.SetX509Authorities(base.X509Authorities())
	for kid, key := range base.JWTAuthorities() {
		s.Require().NoError(withoutHint.AddJWTAuthority(kid, key))
	}
	for kid, key := range base.WITAuthorities() {
		s.Require().NoError(withoutHint.AddWITAuthority(kid, key))
	}
	withoutHint.SetSequenceNumber(1)

	withPath := s.writeBundle("with-hint.json", base)
	withoutPath := s.writeBundle("without-hint.json", withoutHint)

	code := s.cmd.Run([]string{
		"-first", withPath, "-second", withoutPath,
		"-firstTrustDomain", "example.org",
	})
	s.Equal(bundleutil.CompareExitCodeDifferent, code)
	s.Contains(s.stdout.String(), "Refresh hint: 60s -> unset")
}

type fixture struct {
	oldCert *x509.Certificate
	newCert *x509.Certificate

	stableJWT *ecdsa.PrivateKey
	oldRotate *ecdsa.PrivateKey
	newRotate *ecdsa.PrivateKey
	addedJWT  *ecdsa.PrivateKey
	witKey    *ecdsa.PrivateKey
}

// newBaseBundle builds the "before rotation" bundle.
func (s *CompareSuite) newBaseBundle() *spiffebundle.Bundle {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	bundle := spiffebundle.New(td)
	bundle.SetX509Authorities([]*x509.Certificate{s.fixture.oldCert})
	s.Require().NoError(bundle.AddJWTAuthority("stable", &s.fixture.stableJWT.PublicKey))
	s.Require().NoError(bundle.AddJWTAuthority("rotated", &s.fixture.oldRotate.PublicKey))
	s.Require().NoError(bundle.AddWITAuthority("w1", &s.fixture.witKey.PublicKey))
	bundle.SetSequenceNumber(1)
	bundle.SetRefreshHint(60 * time.Second)
	return bundle
}

// newRotatedBundle builds the "after rotation" bundle.
func (s *CompareSuite) newRotatedBundle() *spiffebundle.Bundle {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	bundle := spiffebundle.New(td)
	bundle.SetX509Authorities([]*x509.Certificate{s.fixture.newCert})
	s.Require().NoError(bundle.AddJWTAuthority("stable", &s.fixture.stableJWT.PublicKey))
	s.Require().NoError(bundle.AddJWTAuthority("rotated", &s.fixture.newRotate.PublicKey))
	s.Require().NoError(bundle.AddJWTAuthority("added", &s.fixture.addedJWT.PublicKey))
	s.Require().NoError(bundle.AddWITAuthority("w1", &s.fixture.witKey.PublicKey))
	bundle.SetSequenceNumber(2)
	bundle.SetRefreshHint(120 * time.Second)
	return bundle
}

func (s *CompareSuite) writeFixtureBundles() (string, string) {
	firstPath := s.writeBundle("before.json", s.newBaseBundle())
	secondPath := s.writeBundle("after.json", s.newRotatedBundle())
	return firstPath, secondPath
}

func (s *CompareSuite) writeBundle(name string, bundle *spiffebundle.Bundle) string {
	return s.writeBytes(name, s.mustMarshal(bundle))
}

func (s *CompareSuite) writeBytes(name string, data []byte) string {
	path := filepath.Join(s.dir, name)
	s.Require().NoError(os.WriteFile(path, data, 0o600))
	return path
}

func fingerprintHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *CompareSuite) mustMarshal(bundle *spiffebundle.Bundle) []byte {
	data, err := bundle.Marshal()
	s.Require().NoError(err)
	return data
}

func newFixture(t *testing.T) fixture {
	oldCert := createCert(t, "old-root")
	newCert := createCert(t, "new-root")
	return fixture{
		oldCert:   oldCert,
		newCert:   newCert,
		stableJWT: createKey(t),
		oldRotate: createKey(t),
		newRotate: createKey(t),
		addedJWT:  createKey(t),
		witKey:    createKey(t),
	}
}

var certSerial int64

func createCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key := createKey(t)
	certSerial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(certSerial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func createKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// reorderAndIndent parses SPIFFE bundle JSON and rewrites it with the keys
// slice reversed and indented, simulating a bundle that differs only in order
// and formatting.
func reorderAndIndent(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	if keys, ok := doc["keys"].([]any); ok {
		slices.Reverse(keys)
		doc["keys"] = keys
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	return out
}
