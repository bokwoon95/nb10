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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb10"
)

type StatusCmd struct {
	Notebrew  *nb10.Notebrew
	Stdout    io.Writer
	ConfigDir string
	Port      int
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
	cmd.Port = n
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
	pid, name, err := portPID(cmd.Port)
	if err != nil {
		fmt.Fprintf(cmd.Stdout, "❌ %s\n", err.Error())
	} else if pid != 0 && name != "" {
		fmt.Fprintf(cmd.Stdout, "✔️  %s (pid %d) is listening on port %d\n", name, pid, cmd.Port)
	} else {
		fmt.Fprintf(cmd.Stdout, "❌ could not find any process listening on port %d\n", cmd.Port)
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

func portPID(port int) (pid int, name string, err error) {
	switch runtime.GOOS {
	case "darwin", "linux":
		cmd := exec.Command("lsof", "-n", "-P", "-i", ":"+strconv.Itoa(port))
		b, err := cmd.Output()
		if err != nil {
			// lsof also returns 1 if no result was found, so the way we ensure
			// an error actually occurred is by additionally checking stderr.
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
				return 0, "", fmt.Errorf(string(exitErr.Stderr))
			}
		}
		var line []byte
		remainder := b
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if !bytes.Contains(line, []byte("LISTEN")) && !bytes.Contains(line, []byte("UDP")) {
				continue
			}
			fields := strings.Fields(string(line))
			if len(fields) < 5 {
				continue
			}
			name = strings.TrimSpace(fields[0])
			pid, err = strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				continue
			}
			return pid, name, nil
		}
		return 0, "", nil
	case "windows":
		stderr := &bytes.Buffer{}
		cmd := exec.Command("netstat.exe", "-a", "-n", "-o")
		cmd.Stderr = stderr
		b, err := cmd.Output()
		if err != nil {
			return 0, "", err
		}
		var line []byte
		remainder := b
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			fields := strings.Fields(string(line))
			if len(fields) < 5 {
				continue
			}
			if !strings.HasSuffix(strings.TrimSpace(fields[1]), ":"+strconv.Itoa(port)) {
				continue
			}
			if strings.TrimSpace(fields[3]) != "LISTENING" {
				continue
			}
			pid, err = strconv.Atoi(strings.TrimSpace(fields[4]))
			if err != nil {
				continue
			}
			b, err := exec.Command("tasklist.exe", "/fi", "pid eq "+strconv.Itoa(pid), "/fo", "list").Output()
			if err != nil {
				return 0, "", err
			}
			n := bytes.Index(b, []byte("Image Name:"))
			if n < 0 {
				continue
			}
			start := n + len("Image Name:")
			offset := bytes.Index(b[start:], []byte("\n"))
			if offset < 0 {
				name = string(bytes.TrimSpace(b[start:]))
			} else {
				name = string(bytes.TrimSpace(b[start : start+offset]))
			}
			return pid, name, nil
		}
		return 0, "", nil
	default:
		return 0, "", fmt.Errorf("unable to check if a process is listening on port %d (only macos, linux and windows are supported)", port)
	}
}
