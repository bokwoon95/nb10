package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/porkbun"
	"github.com/mholt/acmez"
	"golang.org/x/sync/errgroup"
)

func NewServer(nbrew *nb10.Notebrew, configDir string) (*http.Server, error) {
	if nbrew.CMSDomain == "" {
		return nil, fmt.Errorf("CMSDomain cannot be empty")
	}
	if nbrew.ContentDomain == "" {
		return nil, fmt.Errorf("ContentDomain cannot be empty")
	}
	addr := ":" + strconv.Itoa(nbrew.Port)
	if nbrew.Port != 443 && nbrew.Port != 80 {
		addr = "localhost" + addr
	}
	server := &http.Server{
		Addr:    addr,
		Handler: nbrew,
	}
	if addr != ":443" {
		return server, nil
	}
	server.ReadTimeout = 60 * time.Second
	server.WriteTimeout = 60 * time.Second
	server.IdleTimeout = 120 * time.Second
	server.Handler = http.TimeoutHandler(nbrew, 60*time.Second, "The server took too long to process your request.")

	var ip4, ip6 netip.Addr
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	group, groupctx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		request, err := http.NewRequest("GET", "https://ipv4.icanhazip.com", nil)
		if err != nil {
			return fmt.Errorf("ipv4.icanhazip.com: %w", err)
		}
		response, err := client.Do(request.WithContext(groupctx))
		if err != nil {
			return fmt.Errorf("ipv4.icanhazip.com: %w", err)
		}
		defer response.Body.Close()
		var b strings.Builder
		_, err = io.Copy(&b, response.Body)
		if err != nil {
			return fmt.Errorf("ipv4.icanhazip.com: %w", err)
		}
		err = response.Body.Close()
		if err != nil {
			return err
		}
		s := strings.TrimSpace(b.String())
		if s == "" {
			return nil
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("ipv4.icanhazip.com: %q is not an IP address", s)
		}
		if ip.Is4() {
			ip4 = ip
		}
		return nil
	})
	group.Go(func() error {
		request, err := http.NewRequest("GET", "https://ipv6.icanhazip.com", nil)
		if err != nil {
			return fmt.Errorf("ipv6.icanhazip.com: %w", err)
		}
		response, err := client.Do(request.WithContext(groupctx))
		if err != nil {
			return fmt.Errorf("ipv6.icanhazip.com: %w", err)
		}
		defer response.Body.Close()
		var b strings.Builder
		_, err = io.Copy(&b, response.Body)
		if err != nil {
			return fmt.Errorf("ipv6.icanhazip.com: %w", err)
		}
		err = response.Body.Close()
		if err != nil {
			return err
		}
		s := strings.TrimSpace(b.String())
		if s == "" {
			return nil
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("ipv6.icanhazip.com: %q is not an IP address", s)
		}
		if ip.Is6() {
			ip6 = ip
		}
		return nil
	})
	err := group.Wait()
	if err != nil {
		return nil, err
	}
	var ip netip.Addr
	if ip4.IsValid() {
		ip = ip4
	} else if ip6.IsValid() {
		ip = ip6
	} else {
		return nil, fmt.Errorf("unable to determine the IP address of the current machine")
	}

	var dns01Solver acmez.Solver
	b, err := os.ReadFile(filepath.Join(configDir, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var dnsConfig struct {
			Provider  string
			Username  string
			APIKey    string
			APIToken  string
			SecretKey string
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
		}
		switch dnsConfig.Provider {
		case "namecheap":
			if dnsConfig.Username == "" {
				return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
			}
			if dnsConfig.APIKey == "" {
				return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
			}
			if !ip.Is4() {
				return nil, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", ip)
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &namecheap.Provider{
					APIKey:      dnsConfig.APIKey,
					User:        dnsConfig.Username,
					APIEndpoint: "https://api.namecheap.com/xml.response",
					ClientIP:    ip.String(),
				},
			}
		case "cloudflare":
			if dnsConfig.APIToken == "" {
				return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &cloudflare.Provider{
					APIToken: dnsConfig.APIToken,
				},
			}
		case "porkbun":
			if dnsConfig.APIKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
			}
			if dnsConfig.SecretKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &porkbun.Provider{
					APIKey:       dnsConfig.APIKey,
					APISecretKey: dnsConfig.SecretKey,
				},
			}
		case "godaddy":
			if dnsConfig.APIToken == "" {
				return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &godaddy.Provider{
					APIToken: dnsConfig.APIToken,
				},
			}
		case "":
			return nil, fmt.Errorf("%s: missing provider field", filepath.Join(configDir, "dns.json"))
		default:
			return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
		}
	}

	b, err = os.ReadFile(filepath.Join(configDir, "certmagic.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.txt"), err)
	}
	certmagicDir := string(bytes.TrimSpace(b))
	if certmagicDir == "" {
		certmagicDir = filepath.Join(configDir, "certmagic")
		err := os.MkdirAll(certmagicDir, 0755)
		if err != nil {
			return nil, err
		}
	} else {
		certmagicDir = filepath.Clean(certmagicDir)
		_, err := os.Stat(certmagicDir)
		if err != nil {
			return nil, err
		}
	}
	certStorage := &certmagic.FileStorage{
		Path: certmagicDir,
	}

	// staticCertConfig manages the certificate for the main domain, content domain
	// and wildcard subdomain.
	staticCertConfig := certmagic.NewDefault()
	staticCertConfig.Storage = certStorage
	staticCertConfig.Issuers = []certmagic.Issuer{
		// Create a new ACME issuer with the dns01Solver because this cert
		// config potentially has to issue wildcard certificates which only the
		// DNS-01 challenge solver is capable of.
		certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
			CA:          certmagic.DefaultACME.CA,
			TestCA:      certmagic.DefaultACME.TestCA,
			Logger:      certmagic.DefaultACME.Logger,
			HTTPProxy:   certmagic.DefaultACME.HTTPProxy,
			DNS01Solver: dns01Solver,
		}),
	}
	var domains []string
	if nbrew.CMSDomain == nbrew.ContentDomain {
		if dns01Solver != nil {
			domains = []string{nbrew.CMSDomain, "*." + nbrew.CMSDomain}
		} else {
			domains = []string{nbrew.CMSDomain, "img." + nbrew.CMSDomain, "www." + nbrew.CMSDomain}
		}
	} else {
		if dns01Solver != nil {
			domains = []string{nbrew.ContentDomain, "*." + nbrew.ContentDomain, nbrew.CMSDomain, "*." + nbrew.CMSDomain}
		} else {
			domains = []string{nbrew.ContentDomain, "img." + nbrew.ContentDomain, nbrew.CMSDomain, "www." + nbrew.CMSDomain, "www." + nbrew.ContentDomain}
		}
	}
	fmt.Printf("notebrew static domains: %v\n", strings.Join(domains, ", "))
	err = staticCertConfig.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}

	// dynamicCertConfig manages the certificates for custom domains.
	//
	// If dns01Solver hasn't been configured, dynamicCertConfig will also be
	// responsible for getting the certificates for subdomains. This approach
	// might get rate limited by Let's Encrypt (up to 50 certificates per
	// week). The safest way to avoid being rate limited is to configure
	// dns01Solver so that the wildcard certificate is available.
	dynamicCertConfig := certmagic.NewDefault()
	dynamicCertConfig.Storage = certStorage
	dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
				return nil
			}
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), name)
			if err != nil {
				return err
			}
			if !fileInfo.IsDir() {
				return fmt.Errorf("%q is not a directory", name)
			}
			return nil
		},
	}

	server.TLSConfig = &tls.Config{
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "" {
				return nil, fmt.Errorf("server name required")
			}
			for _, domain := range domains {
				if certmagic.MatchWildcard(clientHello.ServerName, domain) {
					return staticCertConfig.GetCertificate(clientHello)
				}
			}
			return dynamicCertConfig.GetCertificate(clientHello)
		},
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}
	if cpuid.CPU.Supports(cpuid.AESNI) {
		server.TLSConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	}
	return server, nil
}
