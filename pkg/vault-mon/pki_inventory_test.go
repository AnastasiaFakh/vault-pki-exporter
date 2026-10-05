package vaultmon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestLoadCertsKeepsDistinctSerialsWithSameSubject(t *testing.T) {
	_, caKey, ca := newTestCA(t, "test-ca")
	crlPEM := newTestCRL(t, ca, caKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	crlBlock, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificates := make(map[string]string)
	for _, serial := range []int64{41, 42, 43} {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{
				CommonName:         "1316853",
				OrganizationalUnit: []string{"DevOps"},
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certificates[template.SerialNumber.String()] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/pki_test/certs" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"keys": []string{"41", "42", "43"}}})
			return
		}
		serial := strings.TrimPrefix(r.URL.Path, "/v1/pki_test/cert/")
		if certificate, ok := certificates[serial]; ok {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"certificate": certificate}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	config := vaultapi.DefaultConfig()
	config.Address = server.URL
	client, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	pki := &PKI{
		path:  "pki_test/",
		vault: client,
		certs: make(map[string]*x509.Certificate),
		crls:  map[string]*x509.RevocationList{"test": crl},
	}
	if err := pki.loadCerts(); err != nil {
		t.Fatal(err)
	}
	if len(pki.GetCerts()) != 2 || pki.GetCerts()["41"] == nil || pki.GetCerts()["43"] == nil || pki.GetCerts()["42"] != nil {
		t.Fatalf("expected serials 41 and 43 only, got %#v", pki.GetCerts())
	}
}
