package bundleutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareRejectsNilBundles(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	_, err := Compare(nil, spiffebundle.New(td))
	require.Error(t, err)

	_, err = Compare(spiffebundle.New(td), nil)
	require.Error(t, err)
}

func TestCompareRejectsDifferentTrustDomains(t *testing.T) {
	a := spiffebundle.New(spiffeid.RequireTrustDomainFromString("a.example"))
	b := spiffebundle.New(spiffeid.RequireTrustDomainFromString("b.example"))

	_, err := Compare(a, b)
	require.ErrorIs(t, err, ErrDifferentTrustDomains)
	assert.Contains(t, err.Error(), "a.example")
	assert.Contains(t, err.Error(), "b.example")
}

func TestCompareIdenticalBundles(t *testing.T) {
	_, cert := createCACert(t, "root-1")
	jwtKey, _ := createECDSAKey(t)
	witKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	a := spiffebundle.New(spiffeid.RequireTrustDomainFromString("example.org"))
	a.SetX509Authorities([]*x509.Certificate{cert})
	require.NoError(t, a.AddJWTAuthority("jwt-kid", &jwtKey.PublicKey))
	require.NoError(t, a.AddWITAuthority("wit-kid", witKey))
	a.SetSequenceNumber(7)
	a.SetRefreshHint(5 * time.Minute)

	diff, err := Compare(a, a.Clone())
	require.NoError(t, err)
	assert.False(t, diff.HasDifferences())
	assert.Equal(t, "example.org", diff.TrustDomain)
	assert.Empty(t, diff.X509Authorities.Added)
	assert.Empty(t, diff.X509Authorities.Removed)
	assert.Empty(t, diff.JWTAuthorities.Added)
	assert.Empty(t, diff.JWTAuthorities.Removed)
	assert.Empty(t, diff.JWTAuthorities.Changed)
	assert.Empty(t, diff.WITAuthorities.Added)
	assert.Empty(t, diff.WITAuthorities.Removed)
	assert.Empty(t, diff.WITAuthorities.Changed)
	assert.Nil(t, diff.SequenceNumber)
	assert.Nil(t, diff.RefreshHint)
}

func TestCompareX509OrderInsensitive(t *testing.T) {
	_, cert1 := createCACert(t, "root-1")
	_, cert2 := createCACert(t, "root-2")
	_, cert3 := createCACert(t, "root-3")

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	a.SetX509Authorities([]*x509.Certificate{cert1, cert2, cert3})
	b := spiffebundle.New(td)
	b.SetX509Authorities([]*x509.Certificate{cert3, cert1, cert2})

	diff, err := Compare(a, b)
	require.NoError(t, err)
	assert.False(t, diff.HasDifferences())
}

func TestCompareX509AddedAndRemoved(t *testing.T) {
	_, certRemoved := createCACert(t, "old-root")
	_, certKept := createCACert(t, "kept-root")
	_, certAdded := createCACert(t, "new-root")

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	a.SetX509Authorities([]*x509.Certificate{certRemoved, certKept})
	b := spiffebundle.New(td)
	b.SetX509Authorities([]*x509.Certificate{certKept, certAdded})

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.True(t, diff.HasDifferences())

	require.Len(t, diff.X509Authorities.Removed, 1)
	require.Len(t, diff.X509Authorities.Added, 1)

	removed := diff.X509Authorities.Removed[0]
	added := diff.X509Authorities.Added[0]
	assert.Equal(t, "CN=old-root", removed.Subject)
	assert.Equal(t, fingerprintHex(certRemoved.Raw), removed.SHA256Fingerprint)
	assert.Equal(t, "CN=new-root", added.Subject)
	assert.Equal(t, fingerprintHex(certAdded.Raw), added.SHA256Fingerprint)
	assert.Equal(t, certAdded.NotAfter.Unix(), added.NotAfter.Unix())

	// The same cert re-encoded into a new x509.Certificate is still the same
	// certificate because full contents are compared.
	reparsed, err := x509.ParseCertificate(certKept.Raw)
	require.NoError(t, err)
	c := spiffebundle.New(td)
	c.SetX509Authorities([]*x509.Certificate{reparsed})
	d := spiffebundle.New(td)
	d.SetX509Authorities([]*x509.Certificate{certKept})
	reparsedDiff, err := Compare(c, d)
	require.NoError(t, err)
	assert.False(t, reparsedDiff.HasDifferences())
}

func TestCompareJWTAddedRemovedAndChanged(t *testing.T) {
	_, keyKept := createECDSAKey(t)
	_, keyRemoved := createECDSAKey(t)
	_, keyAdded := createECDSAKey(t)
	_, keyReplacement := createECDSAKey(t)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	require.NoError(t, a.AddJWTAuthority("kept", &keyKept.PublicKey))
	require.NoError(t, a.AddJWTAuthority("removed", &keyRemoved.PublicKey))
	require.NoError(t, a.AddJWTAuthority("replaced", &keyKept.PublicKey))
	b := spiffebundle.New(td)
	require.NoError(t, b.AddJWTAuthority("kept", &keyKept.PublicKey))
	require.NoError(t, b.AddJWTAuthority("added", &keyAdded.PublicKey))
	require.NoError(t, b.AddJWTAuthority("replaced", &keyReplacement.PublicKey))

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.True(t, diff.HasDifferences())

	require.Len(t, diff.JWTAuthorities.Added, 1)
	assert.Equal(t, "added", diff.JWTAuthorities.Added[0].KeyID)
	assert.Equal(t, "EC-P-256", diff.JWTAuthorities.Added[0].KeyType)
	assert.Equal(t, publicKeyFingerprintHex(t, &keyAdded.PublicKey), diff.JWTAuthorities.Added[0].SHA256Fingerprint)

	require.Len(t, diff.JWTAuthorities.Removed, 1)
	assert.Equal(t, "removed", diff.JWTAuthorities.Removed[0].KeyID)

	require.Len(t, diff.JWTAuthorities.Changed, 1)
	change := diff.JWTAuthorities.Changed[0]
	assert.Equal(t, "replaced", change.KeyID)
	assert.Equal(t, publicKeyFingerprintHex(t, &keyKept.PublicKey), change.Before.SHA256Fingerprint)
	assert.Equal(t, publicKeyFingerprintHex(t, &keyReplacement.PublicKey), change.After.SHA256Fingerprint)
	assert.NotEqual(t, change.Before.SHA256Fingerprint, change.After.SHA256Fingerprint)

	// No collateral differences in other authority sets.
	assert.Empty(t, diff.X509Authorities.Added)
	assert.Empty(t, diff.X509Authorities.Removed)
	assert.Empty(t, diff.WITAuthorities.Added)
	assert.Empty(t, diff.WITAuthorities.Removed)
	assert.Empty(t, diff.WITAuthorities.Changed)
}

func TestCompareWITSameKeyIDDifferentMaterial(t *testing.T) {
	_, keyA := createECDSAKey(t)
	_, keyB := createECDSAKey(t)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	require.NoError(t, a.AddWITAuthority("shared-kid", &keyA.PublicKey))
	b := spiffebundle.New(td)
	require.NoError(t, b.AddWITAuthority("shared-kid", &keyB.PublicKey))

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.True(t, diff.HasDifferences())
	require.Len(t, diff.WITAuthorities.Changed, 1)
	assert.Empty(t, diff.WITAuthorities.Added)
	assert.Empty(t, diff.WITAuthorities.Removed)
	assert.Equal(t, "shared-kid", diff.WITAuthorities.Changed[0].KeyID)
}

func TestCompareKeyMovingBetweenUsesIsAddedAndRemoved(t *testing.T) {
	_, key := createECDSAKey(t)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	require.NoError(t, a.AddJWTAuthority("moved", &key.PublicKey))
	b := spiffebundle.New(td)
	require.NoError(t, b.AddWITAuthority("moved", &key.PublicKey))

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.Len(t, diff.JWTAuthorities.Removed, 1)
	assert.Equal(t, "moved", diff.JWTAuthorities.Removed[0].KeyID)
	require.Len(t, diff.WITAuthorities.Added, 1)
	assert.Equal(t, "moved", diff.WITAuthorities.Added[0].KeyID)
	assert.Empty(t, diff.JWTAuthorities.Changed)
	assert.Empty(t, diff.WITAuthorities.Changed)
}

func TestCompareSortsKeyDifferencesByKeyID(t *testing.T) {
	_, zKey := createECDSAKey(t)
	_, mKey := createECDSAKey(t)
	_, aKey := createECDSAKey(t)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	first := spiffebundle.New(td)
	require.NoError(t, first.AddJWTAuthority("zebra", &zKey.PublicKey))
	second := spiffebundle.New(td)
	require.NoError(t, second.AddJWTAuthority("alpha", &aKey.PublicKey))
	require.NoError(t, second.AddJWTAuthority("middle", &mKey.PublicKey))

	diff, err := Compare(first, second)
	require.NoError(t, err)

	require.Len(t, diff.JWTAuthorities.Added, 2)
	assert.Equal(t, []string{"alpha", "middle"}, []string{
		diff.JWTAuthorities.Added[0].KeyID,
		diff.JWTAuthorities.Added[1].KeyID,
	})
	require.Len(t, diff.JWTAuthorities.Removed, 1)
	assert.Equal(t, "zebra", diff.JWTAuthorities.Removed[0].KeyID)
}

func TestCompareSortsCertDifferencesByFingerprint(t *testing.T) {
	_, cert1 := createCACert(t, "root-1")
	_, cert2 := createCACert(t, "root-2")

	td := spiffeid.RequireTrustDomainFromString("example.org")
	a := spiffebundle.New(td)
	a.SetX509Authorities([]*x509.Certificate{cert1, cert2})
	b := spiffebundle.New(td)

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.Len(t, diff.X509Authorities.Removed, 2)
	assert.Less(t,
		diff.X509Authorities.Removed[0].SHA256Fingerprint,
		diff.X509Authorities.Removed[1].SHA256Fingerprint)
}

func TestCompareSequenceNumberMetadata(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	t.Run("unchanged", func(t *testing.T) {
		a := spiffebundle.New(td)
		b := spiffebundle.New(td)
		a.SetSequenceNumber(3)
		b.SetSequenceNumber(3)

		diff, err := Compare(a, b)
		require.NoError(t, err)
		assert.Nil(t, diff.SequenceNumber)
		assert.False(t, diff.HasDifferences())
	})

	t.Run("changed", func(t *testing.T) {
		a := spiffebundle.New(td)
		b := spiffebundle.New(td)
		a.SetSequenceNumber(3)
		b.SetSequenceNumber(4)

		diff, err := Compare(a, b)
		require.NoError(t, err)
		require.NotNil(t, diff.SequenceNumber)
		require.NotNil(t, diff.SequenceNumber.Before)
		require.NotNil(t, diff.SequenceNumber.After)
		assert.Equal(t, uint64(3), *diff.SequenceNumber.Before)
		assert.Equal(t, uint64(4), *diff.SequenceNumber.After)
		assert.True(t, diff.HasDifferences())
	})

	t.Run("set", func(t *testing.T) {
		a := spiffebundle.New(td)
		b := spiffebundle.New(td)
		b.SetSequenceNumber(1)

		diff, err := Compare(a, b)
		require.NoError(t, err)
		require.NotNil(t, diff.SequenceNumber)
		assert.Nil(t, diff.SequenceNumber.Before)
		require.NotNil(t, diff.SequenceNumber.After)
		assert.Equal(t, uint64(1), *diff.SequenceNumber.After)
	})

	t.Run("cleared", func(t *testing.T) {
		a := spiffebundle.New(td)
		b := spiffebundle.New(td)
		a.SetSequenceNumber(1)

		diff, err := Compare(a, b)
		require.NoError(t, err)
		require.NotNil(t, diff.SequenceNumber)
		require.NotNil(t, diff.SequenceNumber.Before)
		assert.Nil(t, diff.SequenceNumber.After)
	})
}

func TestCompareRefreshHintMetadata(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	a := spiffebundle.New(td)
	b := spiffebundle.New(td)
	a.SetRefreshHint(60 * time.Second)
	b.SetRefreshHint(2 * time.Minute)

	diff, err := Compare(a, b)
	require.NoError(t, err)
	require.NotNil(t, diff.RefreshHint)
	require.NotNil(t, diff.RefreshHint.BeforeSeconds)
	require.NotNil(t, diff.RefreshHint.AfterSeconds)
	assert.Equal(t, int64(60), *diff.RefreshHint.BeforeSeconds)
	assert.Equal(t, int64(120), *diff.RefreshHint.AfterSeconds)
	assert.True(t, diff.HasDifferences())

	// Metadata changes do not appear in the authority sections.
	assert.Empty(t, diff.X509Authorities.Added)
	assert.Empty(t, diff.JWTAuthorities.Changed)
	assert.Empty(t, diff.WITAuthorities.Changed)
}

func TestDescribeKeyTypes(t *testing.T) {
	_, ecKey := createECDSAKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, "EC-P-256", keyType(&ecKey.PublicKey))
	assert.Equal(t, "RSA-2048", keyType(&rsaKey.PublicKey))
	assert.Equal(t, "Ed25519", keyType(edPub))
}

var certSerialCounter int64

func createCACert(t *testing.T, commonName string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certSerialCounter++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(certSerialCounter),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func createECDSAKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, key
}

func fingerprintHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func publicKeyFingerprintHex(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return fingerprintHex(der)
}
