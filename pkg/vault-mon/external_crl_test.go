package vaultmon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseExternalCRLSources(t *testing.T) {
	sources, err := parseExternalCRLSources([]string{
		"pki_cs_partner_test=app/data/cs.partner/pki/ca-crl:ca.crl",
	})
	if err != nil {
		t.Fatal(err)
	}

	source, ok := sources["pki_cs_partner_test/"]
	if !ok {
		t.Fatal("normalized PKI mount not found")
	}
	if source.path != "app/data/cs.partner/pki/ca-crl" || source.field != "ca.crl" {
		t.Fatalf("unexpected source: %#v", source)
	}
}

func TestParseExternalCRLSourcesRejectsInvalidValue(t *testing.T) {
	if _, err := parseExternalCRLSources([]string{"pki_cs_partner_test"}); err == nil {
		t.Fatal("expected invalid mapping to fail")
	}
}

func TestParseAndValidateExternalCRL(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, key, ca := newTestCA(t, "cs-partner")
	crlPEM := newTestCRL(t, ca, key, now.Add(-time.Hour), now.Add(time.Hour))

	crl, err := parseAndValidateExternalCRL(crlPEM, caPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("unexpected revoked certificates: %#v", crl.RevokedCertificateEntries)
	}
}

func TestParseAndValidateExternalCRLRejectsExpiredCRL(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caPEM, key, ca := newTestCA(t, "cs-partner")
	crlPEM := newTestCRL(t, ca, key, now.Add(-2*time.Hour), now.Add(-time.Hour))

	if _, err := parseAndValidateExternalCRL(crlPEM, caPEM, now); err == nil {
		t.Fatal("expected expired CRL to fail")
	}
}

func TestParseAndValidateExternalCRLRejectsDifferentCA(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, key, ca := newTestCA(t, "cs-partner")
	otherCAPEM, _, _ := newTestCA(t, "other")
	crlPEM := newTestCRL(t, ca, key, now.Add(-time.Hour), now.Add(time.Hour))

	if _, err := parseAndValidateExternalCRL(crlPEM, otherCAPEM, now); err == nil {
		t.Fatal("expected CRL signed by a different CA to fail")
	}
}

func newTestCA(t *testing.T, commonName string) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, ca
}

func newTestCRL(t *testing.T, ca *x509.Certificate, key *rsa.PrivateKey, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(10),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: thisUpdate},
		},
	}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
