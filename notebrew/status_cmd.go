package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/netstat"
)

type StatusCmd struct {
	Notebrew  *nb10.Notebrew
	Stdout    io.Writer
	ConfigDir string
	Port      uint16
}

func StatusCommand(nbrew *nb10.Notebrew, configDir string, addr string, args ...string) (*StatusCmd, error) {
	var cmd StatusCmd
	cmd.Notebrew = nbrew
	cmd.ConfigDir = configDir
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(addr, "localhost"), ":"))
	if err != nil {
		return nil, err
	}
	cmd.Port = uint16(n)
	return &cmd, nil
}

func (cmd *StatusCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dataHomeDir := os.Getenv("XDG_DATA_HOME")
	if dataHomeDir == "" {
		dataHomeDir = homeDir
	}
	sockTabEntries, err := netstat.TCPSocks(func(sockTabEntry *netstat.SockTabEntry) bool {
		return sockTabEntry.State == netstat.Listen && sockTabEntry.LocalAddr.Port == cmd.Port
	})
	if err != nil {
		return err
	}
	if len(sockTabEntries) == 0 {
		fmt.Fprintf(cmd.Stdout, "❌ notebrew is not running\n")
	} else {
		sockTabEntry := sockTabEntries[0]
		fmt.Fprintf(cmd.Stdout, "✔  notebrew is running (pid %d)\n", sockTabEntry.Process.Pid)
	}
	fmt.Fprintf(cmd.Stdout, "port          = %d\n", cmd.Port)
	fmt.Fprintf(cmd.Stdout, "cmsdomain     = %s\n", cmd.Notebrew.CMSDomain)
	fmt.Fprintf(cmd.Stdout, "contentdomain = %s\n", cmd.Notebrew.ContentDomain)
	if cmd.Notebrew.ImgDomain == "" {
		fmt.Fprintf(cmd.Stdout, "imgdomain     = <not configured>\n")
	} else {
		fmt.Fprintf(cmd.Stdout, "imgdomain     = %s\n", cmd.Notebrew.ImgDomain)
	}

	// Database.
	b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(cmd.Stdout, "database      = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "database.json"), err)
	} else {
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			fmt.Fprintf(cmd.Stdout, "database      = <not configured>\n")
		} else {
			var databaseConfig DatabaseConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				fmt.Fprintf(cmd.Stdout, "database      = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "database.json"), err)
			} else {
				switch databaseConfig.Dialect {
				case "":
					fmt.Fprintf(cmd.Stdout, "database      = <not configured>\n")
				case "sqlite":
					var filePath string
					if databaseConfig.FilePath == "" {
						filePath = filepath.Join(dataHomeDir, "notebrew-database.db")
					} else {
						databaseConfig.FilePath = filepath.Clean(databaseConfig.FilePath)
						filePath, err = filepath.Abs(databaseConfig.FilePath)
						if err != nil {
							filePath = databaseConfig.FilePath
						}
					}
					fmt.Fprintf(cmd.Stdout, "database      = %s (%s)\n", databaseConfig.Dialect, filePath)
				default:
					fmt.Fprintf(cmd.Stdout, "database      = %s (%s:%s/%s)\n", databaseConfig.Dialect, databaseConfig.Host, databaseConfig.Port, databaseConfig.DBName)
				}
			}
		}
	}

	// Files.
	b, err = os.ReadFile(filepath.Join(cmd.ConfigDir, "files.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(cmd.Stdout, "files         = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "files.json"), err)
	} else {
		b = bytes.TrimSpace(b)
		var filesConfig DatabaseConfig
		var decodeError error
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			decodeError = decoder.Decode(&filesConfig)
		}
		if decodeError != nil {
			fmt.Fprintf(cmd.Stdout, "files         = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "files.json"), err)
		} else if filesConfig.Dialect == "" {
			var filePath string
			if filesConfig.FilePath == "" {
				filePath = filepath.Join(dataHomeDir, "notebrew-files")
			} else {
				filesConfig.FilePath = filepath.Clean(filesConfig.FilePath)
				filePath, err = filepath.Abs(filesConfig.FilePath)
				if err != nil {
					filePath = filesConfig.FilePath
				}
			}
			fmt.Fprintf(cmd.Stdout, "files         = %s\n", filePath)
		} else {
			if filesConfig.Dialect == "sqlite" {
				var filePath string
				if filesConfig.FilePath == "" {
					filePath = filepath.Join(dataHomeDir, "notebrew-files.db")
				} else {
					filesConfig.FilePath = filepath.Clean(filesConfig.FilePath)
					filePath, err = filepath.Abs(filesConfig.FilePath)
					if err != nil {
						filePath = filesConfig.FilePath
					}
				}
				fmt.Fprintf(cmd.Stdout, "files         = %s (%s)\n", filesConfig.Dialect, filePath)
			} else {
				fmt.Fprintf(cmd.Stdout, "files         = %s (%s:%s/%s)\n", filesConfig.Dialect, filesConfig.Host, filesConfig.Port, filesConfig.DBName)
			}
			// Objects.
			b, err = os.ReadFile(filepath.Join(cmd.ConfigDir, "objects.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintf(cmd.Stdout, "objects       = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "objects.json"), err)
			} else {
				b = bytes.TrimSpace(b)
				var objectsConfig ObjectsConfig
				var decodeError error
				if len(b) > 0 {
					decoder := json.NewDecoder(bytes.NewReader(b))
					decoder.DisallowUnknownFields()
					decodeError = decoder.Decode(&objectsConfig)
				}
				if decodeError != nil {
					fmt.Fprintf(cmd.Stdout, "objects       = <error: %s: %s>\n", filepath.Join(cmd.ConfigDir, "objects.json"), err)
				} else if objectsConfig.Provider == "" || objectsConfig.Provider == "local" {
					var filePath string
					if objectsConfig.FilePath == "" {
						filePath = filepath.Join(dataHomeDir, "notebrew-objects")
					} else {
						objectsConfig.FilePath = filepath.Clean(objectsConfig.FilePath)
						filePath, err = filepath.Abs(objectsConfig.FilePath)
						if err != nil {
							filePath = objectsConfig.FilePath
						}
					}
					fmt.Fprintf(cmd.Stdout, "objects       = %s\n", filePath)
				} else {
					fmt.Fprintf(cmd.Stdout, "objects       = %s/%s\n", objectsConfig.Endpoint, objectsConfig.Bucket)
				}
			}
		}
	}

	// Captcha.
	if cmd.Notebrew.CaptchaConfig.VerificationURL == "" {
		fmt.Fprintf(cmd.Stdout, "captcha       = <not configured>\n")
	} else {
		fmt.Fprintf(cmd.Stdout, "captcha       = %s\n", cmd.Notebrew.CaptchaConfig.VerificationURL)
	}

	// Proxy.
	var proxies []string
	seen := make(map[netip.Addr]bool)
	for addr := range cmd.Notebrew.ProxyConfig.RealIPHeaders {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		proxies = append(proxies, addr.String())
	}
	for addr := range cmd.Notebrew.ProxyConfig.ProxyIPs {
		if seen[addr] {
			continue
		}
		proxies = append(proxies, addr.String())
	}
	if len(proxies) == 0 {
		fmt.Fprintf(cmd.Stdout, "proxy         = <not configured>\n")
	} else {
		fmt.Fprintf(cmd.Stdout, "proxy         = %s\n", strings.Join(proxies, ", "))
	}

	if cmd.Port == 443 {
		// DNS.
		b, err = os.ReadFile(filepath.Join(cmd.ConfigDir, "dns.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			fmt.Fprintf(cmd.Stdout, "dns           = <not configured>\n")
		} else {
			var dnsConfig DNSConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&dnsConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "dns.json"), err)
			}
			fmt.Fprintf(cmd.Stdout, "dns           = %s\n", dnsConfig.Provider)
		}

		// Certmagic.
		b, err = os.ReadFile(filepath.Join(cmd.ConfigDir, "certmagic.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			fmt.Fprintf(cmd.Stdout, "certmagic     = %s\n", filepath.Join(cmd.ConfigDir, "certmagic"))
		} else {
			var filePath string
			cleaned := filepath.Clean(string(b))
			filePath, err := filepath.Abs(cleaned)
			if err != nil {
				filePath = cleaned
			}
			fmt.Fprintf(cmd.Stdout, "certmagic     = %s\n", filePath)
		}
	}
	fmt.Fprintf(cmd.Stdout, "To configure the above settings, run `notebrew config`.\n")
	return nil
}
