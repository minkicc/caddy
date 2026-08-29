// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package aliyuncdn provides an event handler which synchronizes managed
// certificates to Alibaba Cloud CDN.
package aliyuncdn

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler synchronizes certificates obtained by CertMagic to Alibaba Cloud CDN.
type Handler struct {
	// Alibaba Cloud access key ID. Placeholders such as {$ALIYUN_ACCESS_KEY_ID}
	// are supported.
	AccessKeyID string `json:"access_key_id,omitempty"`
	// Alibaba Cloud access key secret. Placeholders are supported.
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	// Optional STS security token.
	SecurityToken string `json:"security_token,omitempty"`
	// Alibaba Cloud region. It is sent to the CDN RPC API when set.
	Region string `json:"region,omitempty"`
	// Optional CDN API endpoint. The default is https://cdn.aliyuncs.com.
	Endpoint string `json:"endpoint,omitempty"`
	// Accelerated domain names to update. Up to 10 names are sent per request.
	Domains []string `json:"domains,omitempty"`
	// Certificate name in Alibaba Cloud. If empty, the certificate identifier is used.
	CertName string `json:"cert_name,omitempty"`
	// If true, overwrite an existing certificate with the same name.
	ForceSet bool `json:"force_set,omitempty"`

	storage certmagic.Storage
	client  *http.Client
	logger  *zap.Logger
}

// CaddyModule returns the module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.aliyun_cdn",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision prepares the handler for use.
func (h *Handler) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	var err error
	for field, value := range map[string]*string{
		"access_key_id":     &h.AccessKeyID,
		"access_key_secret": &h.AccessKeySecret,
		"security_token":    &h.SecurityToken,
		"region":            &h.Region,
		"endpoint":          &h.Endpoint,
		"cert_name":         &h.CertName,
	} {
		if *value == "" {
			continue
		}
		*value, err = repl.ReplaceOrErr(*value, true, true)
		if err != nil {
			return fmt.Errorf("invalid %s: %v", field, err)
		}
	}
	if h.AccessKeyID == "" || h.AccessKeySecret == "" {
		return errors.New("access_key_id and access_key_secret are required")
	}
	if len(h.Domains) == 0 {
		return errors.New("at least one CDN domain is required")
	}
	for i, domain := range h.Domains {
		h.Domains[i], err = repl.ReplaceOrErr(domain, true, true)
		if err != nil {
			return fmt.Errorf("invalid domain: %v", err)
		}
		h.Domains[i] = strings.TrimSpace(h.Domains[i])
		if h.Domains[i] == "" {
			return errors.New("CDN domains must not be empty")
		}
	}
	if h.Endpoint == "" {
		h.Endpoint = "https://cdn.aliyuncs.com"
	}
	u, err := url.Parse(h.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("endpoint must be an HTTPS URL")
	}
	h.storage = ctx.Storage()
	h.client = &http.Client{Timeout: 30 * time.Second}
	h.logger = ctx.Logger()
	return nil
}

// Validate validates the handler configuration.
func (h *Handler) Validate() error {
	if len(h.Domains) == 0 {
		return errors.New("at least one CDN domain is required")
	}
	return nil
}

// Handle synchronizes a newly obtained or renewed certificate.
func (h *Handler) Handle(ctx context.Context, event caddy.Event) error {
	if event.Name() != "cert_obtained" {
		return nil
	}
	identifier, ok := event.Data["identifier"].(string)
	if !ok || identifier == "" {
		return errors.New("cert_obtained event has no identifier")
	}
	certKey, ok := event.Data["certificate_path"].(string)
	if !ok || certKey == "" {
		return errors.New("cert_obtained event has no certificate path")
	}
	privateKeyKey, ok := event.Data["private_key_path"].(string)
	if !ok || privateKeyKey == "" {
		return errors.New("cert_obtained event has no private key path")
	}
	certPEM, err := h.storage.Load(ctx, certKey)
	if err != nil {
		return fmt.Errorf("loading certificate from storage: %w", err)
	}
	keyPEM, err := h.storage.Load(ctx, privateKeyKey)
	if err != nil {
		return fmt.Errorf("loading private key from storage: %w", err)
	}
	if err := validateCertificate(certPEM, h.Domains); err != nil {
		return err
	}
	certName := h.CertName
	if certName == "" {
		certName = identifier
	}
	if err := h.updateCDN(ctx, certName, string(certPEM), string(keyPEM)); err != nil {
		return err
	}
	h.logger.Info("synchronized certificate to Alibaba Cloud CDN", zap.Strings("domains", h.Domains), zap.String("certificate", certName))
	return nil
}

func validateCertificate(certPEM []byte, domains []string) error {
	var rest = certPEM
	var certs []*x509.Certificate
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return errors.New("certificate does not contain a PEM certificate")
	}
	for _, domain := range domains {
		if err := certs[0].VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate does not cover CDN domain %q: %w", domain, err)
		}
	}
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	aliyun_cdn {
//		access_key_id <id>
//		access_key_secret <secret>
//		security_token <token>
//		region <region>
//		endpoint <https-url>
//		domains <domain> [<domain> ...]
//		cert_name <name>
//		force_set
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		switch d.Val() {
		case "access_key_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.AccessKeyID = d.Val()
		case "access_key_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.AccessKeySecret = d.Val()
		case "security_token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.SecurityToken = d.Val()
		case "region":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Region = d.Val()
		case "endpoint":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Endpoint = d.Val()
		case "domains":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Domains = append(h.Domains, d.Val())
			for d.NextArg() {
				h.Domains = append(h.Domains, d.Val())
			}
		case "cert_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.CertName = d.Val()
		case "force_set":
			h.ForceSet = true
		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
		if d.NextArg() && d.Val() != "" {
			return d.ArgErr()
		}
	}
	return nil
}

func (h *Handler) updateCDN(ctx context.Context, certName, certPEM, keyPEM string) error {
	params := map[string]string{
		"AccessKeyId":      h.AccessKeyID,
		"Action":           "BatchSetCdnDomainServerCertificate",
		"CertName":         certName,
		"CertType":         "upload",
		"DomainName":       strings.Join(h.Domains, ","),
		"Format":           "JSON",
		"ForceSet":         boolString(h.ForceSet),
		"SSLPri":           keyPEM,
		"SSLProtocol":      "on",
		"SSLPub":           certPEM,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   uuid.NewString(),
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2018-05-10",
	}
	if h.Region != "" {
		params["Region"] = h.Region
	}
	if h.SecurityToken != "" {
		params["SecurityToken"] = h.SecurityToken
	}
	params["Signature"] = sign(params, h.AccessKeySecret)
	form := url.Values{}
	for key, value := range params {
		form.Set(key, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("creating Alibaba Cloud CDN request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("calling Alibaba Cloud CDN: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading Alibaba Cloud CDN response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Alibaba Cloud CDN returned HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var apiResponse struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &apiResponse); err == nil && apiResponse.Code != "" {
		return fmt.Errorf("Alibaba Cloud CDN rejected certificate update: %s (%s)", apiResponse.Code, apiResponse.Message)
	}
	return nil
}

func sign(params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, key := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(key))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[key]))
	}
	stringToSign := "POST&%2F&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func percentEncode(value string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(value))
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// Interface guards
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddy.Validator       = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyevents.Handler   = (*Handler)(nil)
)
