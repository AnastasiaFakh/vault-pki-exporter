package vaultmon

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type externalCRLSource struct {
	path  string
	field string
}

var externalCRLUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "x509_external_crl_up",
	Help: "Whether the external CRL configured for a PKI mount was loaded and validated successfully",
}, []string{"source"})

func parseExternalCRLSources(values []string) (map[string]externalCRLSource, error) {
	sources := make(map[string]externalCRLSource, len(values))

	for _, value := range values {
		mount, location, ok := strings.Cut(value, "=")
		separator := strings.LastIndex(location, ":")
		if !ok || strings.TrimSpace(mount) == "" || separator <= 0 || separator == len(location)-1 {
			return nil, fmt.Errorf("invalid external CRL mapping %q: expected <pki-mount>=<kv-api-path>:<field>", value)
		}

		mount = strings.Trim(strings.TrimSpace(mount), "/") + "/"
		source := externalCRLSource{
			path:  strings.Trim(strings.TrimSpace(location[:separator]), "/"),
			field: strings.TrimSpace(location[separator+1:]),
		}
		if existing, exists := sources[mount]; exists {
			if existing == source {
				continue
			}
			return nil, fmt.Errorf("external CRL has conflicting configurations for %s", mount)
		}

		sources[mount] = source
	}

	return sources, nil
}

func (pki *PKI) loadExternalCRL(now time.Time) (*x509.RevocationList, int, error) {
	secret, err := pki.vault.Logical().Read(pki.externalCRL.path)
	if err != nil {
		return nil, 0, fmt.Errorf("read external CRL from %s: %w", pki.externalCRL.path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, 0, fmt.Errorf("external CRL secret not found at %s", pki.externalCRL.path)
	}

	kv := vault.KVVersion2{}
	if err := mapstructure.WeakDecode(secret.Data, &kv); err != nil {
		return nil, 0, fmt.Errorf("decode KV v2 secret at %s: %w", pki.externalCRL.path, err)
	}
	crlPEM, ok := kv.Data[pki.externalCRL.field].(string)
	if !ok || strings.TrimSpace(crlPEM) == "" {
		return nil, 0, fmt.Errorf("external CRL field %s is missing at %s", pki.externalCRL.field, pki.externalCRL.path)
	}

	caSecret, err := pki.vault.Logical().Read(fmt.Sprintf("%scert/ca", pki.path))
	if err != nil {
		return nil, 0, fmt.Errorf("read CA certificate for %s: %w", pki.path, err)
	}
	if caSecret == nil || caSecret.Data == nil {
		return nil, 0, fmt.Errorf("CA certificate not found for %s", pki.path)
	}
	caPEM, ok := caSecret.Data["certificate"].(string)
	if !ok || strings.TrimSpace(caPEM) == "" {
		return nil, 0, fmt.Errorf("CA certificate is missing for %s", pki.path)
	}

	crl, err := parseAndValidateExternalCRL([]byte(crlPEM), []byte(caPEM), now)
	if err != nil {
		return nil, 0, fmt.Errorf("validate external CRL for %s: %w", pki.path, err)
	}

	return crl, len(crlPEM), nil
}

func parseAndValidateExternalCRL(crlPEM, caPEM []byte, now time.Time) (*x509.RevocationList, error) {
	crlBlock := findPEMBlock(crlPEM, "X509 CRL")
	if crlBlock == nil {
		return nil, fmt.Errorf("X509 CRL PEM block not found")
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	caBlock := findPEMBlock(caPEM, "CERTIFICATE")
	if caBlock == nil {
		return nil, fmt.Errorf("CA certificate PEM block not found")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
		return nil, fmt.Errorf("CRL issuer does not match PKI CA subject")
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return nil, fmt.Errorf("verify CRL signature: %w", err)
	}
	if now.Before(crl.ThisUpdate) {
		return nil, fmt.Errorf("CRL is not valid before %s", crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if crl.NextUpdate.IsZero() || !now.Before(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL expired at %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}

	return crl, nil
}

func findPEMBlock(data []byte, blockType string) *pem.Block {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type == blockType {
			return block
		}
		data = rest
	}
	return nil
}
