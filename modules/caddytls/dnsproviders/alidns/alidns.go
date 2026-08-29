// Copyright 2020 Yu Zhu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package alidns

import (
	libdnsalidns "github.com/libdns/alidns"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Provider wraps the libdns AliDNS provider as a Caddy module.
type Provider struct {
	*libdnsalidns.Provider
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.alidns",
		New: func() caddy.Module { return &Provider{Provider: new(libdnsalidns.Provider)} },
	}
}

// Provision resolves environment placeholders in the provider credentials.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.AccessKeyID = repl.ReplaceAll(p.Provider.AccessKeyID, "")
	p.Provider.AccessKeySecret = repl.ReplaceAll(p.Provider.AccessKeySecret, "")
	p.Provider.SecurityToken = repl.ReplaceAll(p.Provider.SecurityToken, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "access_key_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.AccessKeyID = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "access_key_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.AccessKeySecret = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "region_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.RegionID = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "security_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.SecurityToken = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	if p.AccessKeyID == "" || p.AccessKeySecret == "" {
		return d.Err("access_key_id or access_key_secret is empty")
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
