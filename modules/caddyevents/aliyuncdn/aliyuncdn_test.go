package aliyuncdn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestSign(t *testing.T) {
	params := map[string]string{
		"AccessKeyId": "testid",
		"Action":      "BatchSetCdnDomainServerCertificate",
		"Format":      "JSON",
		"Version":     "2018-05-10",
	}
	got := sign(params, "testsecret")
	if got == "" {
		t.Fatal("expected signature")
	}
	if got != sign(params, "testsecret") {
		t.Fatal("signature is not deterministic")
	}
	if got == sign(params, "othersecret") {
		t.Fatal("signature does not depend on secret")
	}
}

func TestValidateCertificate(t *testing.T) {
	certPEM := testCertificatePEM(t, "cdn.example.com")
	if err := validateCertificate(certPEM, []string{"cdn.example.com"}); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	if err := validateCertificate(certPEM, []string{"other.example.com"}); err == nil {
		t.Fatal("certificate for another domain was accepted")
	}
}

func TestHandleUpdatesCDN(t *testing.T) {
	certPEM := testCertificatePEM(t, "cdn.example.com")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n")
	storage := &memoryStorage{values: map[string][]byte{
		"cert": certPEM,
		"key":  keyPEM,
	}}
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"RequestId":"ok"}`))
	}))
	defer server.Close()

	h := &Handler{
		AccessKeyID:     "id",
		AccessKeySecret: "secret",
		Endpoint:        server.URL,
		Domains:         []string{"cdn.example.com"},
		storage:         storage,
		client:          server.Client(),
		logger:          zap.NewNop(),
	}
	event, err := caddy.NewEvent(caddy.Context{Context: context.Background()}, "cert_obtained", map[string]any{
		"identifier":       "cdn.example.com",
		"certificate_path": "cert",
		"private_key_path": "key",
	})
	if err != nil {
		t.Fatalf("creating event: %v", err)
	}
	if err := h.Handle(context.Background(), event); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}
	if gotForm.Get("DomainName") != "cdn.example.com" {
		t.Fatalf("DomainName = %q", gotForm.Get("DomainName"))
	}
	if gotForm.Get("SSLPri") != string(keyPEM) {
		t.Fatal("private key was not sent to CDN")
	}
	if gotForm.Get("SSLProtocol") != "on" || gotForm.Get("CertType") != "upload" {
		t.Fatal("certificate upload options are incorrect")
	}
}

func testCertificatePEM(t *testing.T, name string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type memoryStorage struct {
	values map[string][]byte
}

func (s *memoryStorage) Store(_ context.Context, key string, value []byte) error {
	s.values[key] = append([]byte(nil), value...)
	return nil
}
func (s *memoryStorage) Load(_ context.Context, key string) ([]byte, error) {
	value, ok := s.values[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return value, nil
}
func (s *memoryStorage) Delete(_ context.Context, key string) error {
	delete(s.values, key)
	return nil
}
func (s *memoryStorage) Exists(_ context.Context, key string) bool                  { _, ok := s.values[key]; return ok }
func (s *memoryStorage) List(_ context.Context, _ string, _ bool) ([]string, error) { return nil, nil }
func (s *memoryStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	if !s.Exists(context.Background(), key) {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}
	return certmagic.KeyInfo{Key: key, IsTerminal: true}, nil
}
func (s *memoryStorage) Lock(context.Context, string) error   { return nil }
func (s *memoryStorage) Unlock(context.Context, string) error { return nil }
