package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const configHelp = `Usage:
  notebrew config [KEY]                           # print the value of the key
  notebrew config [KEY] [VALUE]                   # set the value of the key
  notebrew config port                            # prints the value of port
  notebrew config port 443                        # sets the value of port to 443
  notebrew config database                        # prints the database configuration
  notebrew config database '{"dialect":"sqlite"}' # sets the database configuration
  notebrew config database.dialect sqlite         # sets the database dialect to sqlite

Keys:
  notebrew config port          # (txt) The port that notebrew listens on.
  notebrew config cmsdomain     # (txt) The domain that the CMS is served on.
  notebrew config contentdomain # (txt) The domain that the content is served on.
  notebrew config imgdomain     # (txt) The domain that images are served on.
  notebrew config database      # (json) Database configuration.
  notebrew config files         # (json) File system configuration.
  notebrew config objects       # (json) Object storage configuration.
  notebrew config captcha       # (json) Captcha configuration.
  notebrew config dns           # (json) DNS provider configuration.
  notebrew config certmagic     # (txt) certmagic directory for storing SSL certificates.
`

type ConfigCmd struct {
	ConfigDir string
	Stdout    io.Writer
	Stderr    io.Writer
	Key       sql.NullString
	Value     sql.NullString
}

func ConfigCommand(configDir string, args ...string) (*ConfigCmd, error) {
	var cmd ConfigCmd
	cmd.ConfigDir = configDir
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		io.WriteString(flagset.Output(), configHelp)
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	args = flagset.Args()
	switch len(args) {
	case 0:
		break
	case 1:
		cmd.Key = sql.NullString{String: args[0], Valid: true}
	case 2:
		cmd.Key = sql.NullString{String: args[0], Valid: true}
		if strings.HasPrefix(args[1], "-") {
			return &cmd, nil
		}
		cmd.Value = sql.NullString{String: args[1], Valid: true}
	default:
		return nil, fmt.Errorf("too many arguments (max 2)")
	}
	return &cmd, nil
}

func (cmd *ConfigCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	if !cmd.Key.Valid {
		io.WriteString(cmd.Stderr, configHelp)
		return nil
	}
	head, tail, _ := strings.Cut(cmd.Key.String, ".")
	if !cmd.Value.Valid {
		switch head {
		case "":
			return fmt.Errorf("key cannot be empty")
		case "port":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "port.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			io.WriteString(cmd.Stdout, string(bytes.TrimSpace(b))+"\n")
		case "cmsdomain":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "cmsdomain.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			io.WriteString(cmd.Stdout, string(bytes.TrimSpace(b))+"\n")
		case "contentdomain":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "contentdomain.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			io.WriteString(cmd.Stdout, string(bytes.TrimSpace(b))+"\n")
		case "imgdomain":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "imgdomain.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			io.WriteString(cmd.Stdout, string(bytes.TrimSpace(b))+"\n")
		case "database":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "database.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			var databaseConfig DatabaseConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&databaseConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "database.json"), err)
				}
			}
			if databaseConfig.Params == nil {
				databaseConfig.Params = map[string]string{}
			}
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, databaseHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(databaseConfig)
				if err != nil {
					return err
				}
			case "dialect":
				io.WriteString(cmd.Stdout, databaseConfig.Dialect+"\n")
			case "filePath":
				io.WriteString(cmd.Stdout, databaseConfig.FilePath+"\n")
			case "user":
				io.WriteString(cmd.Stdout, databaseConfig.User+"\n")
			case "password":
				io.WriteString(cmd.Stdout, databaseConfig.Password+"\n")
			case "host":
				io.WriteString(cmd.Stdout, databaseConfig.Host+"\n")
			case "port":
				io.WriteString(cmd.Stdout, databaseConfig.Port+"\n")
			case "dbName":
				io.WriteString(cmd.Stdout, databaseConfig.DBName+"\n")
			case "params":
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(databaseConfig.Params)
				if err != nil {
					return err
				}
			default:
				io.WriteString(cmd.Stderr, databaseHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		case "files":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "files.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			var filesConfig DatabaseConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&filesConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "files.json"), err)
				}
			}
			if filesConfig.Params == nil {
				filesConfig.Params = map[string]string{}
			}
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, filesHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(filesConfig)
				if err != nil {
					return err
				}
			case "dialect":
				io.WriteString(cmd.Stdout, filesConfig.Dialect+"\n")
			case "filePath":
				io.WriteString(cmd.Stdout, filesConfig.FilePath+"\n")
			case "user":
				io.WriteString(cmd.Stdout, filesConfig.User+"\n")
			case "password":
				io.WriteString(cmd.Stdout, filesConfig.Password+"\n")
			case "host":
				io.WriteString(cmd.Stdout, filesConfig.Host+"\n")
			case "port":
				io.WriteString(cmd.Stdout, filesConfig.Port+"\n")
			case "dbName":
				io.WriteString(cmd.Stdout, filesConfig.DBName+"\n")
			case "params":
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(filesConfig.Params)
				if err != nil {
					return err
				}
			default:
				io.WriteString(cmd.Stderr, filesHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		case "objects":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "objects.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			var objectsConfig ObjectsConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&objectsConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "objects.json"), err)
				}
			}
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, objectsHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(objectsConfig)
				if err != nil {
					return err
				}
			case "provider":
				io.WriteString(cmd.Stdout, objectsConfig.Provider+"\n")
			case "filePath":
				io.WriteString(cmd.Stdout, objectsConfig.FilePath+"\n")
			case "endpoint":
				io.WriteString(cmd.Stdout, objectsConfig.Endpoint+"\n")
			case "region":
				io.WriteString(cmd.Stdout, objectsConfig.Region+"\n")
			case "bucket":
				io.WriteString(cmd.Stdout, objectsConfig.Bucket+"\n")
			case "accessKeyID":
				io.WriteString(cmd.Stdout, objectsConfig.AccessKeyID+"\n")
			case "secretAccessKey":
				io.WriteString(cmd.Stdout, objectsConfig.SecretAccessKey+"\n")
			default:
				io.WriteString(cmd.Stderr, objectsHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		case "captcha":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "captcha.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			var captchaConfig CaptchaConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&captchaConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "captcha.json"), err)
				}
			}
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, captchaHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(captchaConfig)
				if err != nil {
					return err
				}
			case "verificationURL":
				io.WriteString(cmd.Stdout, captchaConfig.VerificationURL+"\n")
			case "siteKey":
				io.WriteString(cmd.Stdout, captchaConfig.SiteKey+"\n")
			case "secretKey":
				io.WriteString(cmd.Stdout, captchaConfig.SecretKey+"\n")
			default:
				io.WriteString(cmd.Stderr, captchaHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		case "dns":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "dns.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			var dnsConfig DNSConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&dnsConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "dns.json"), err)
				}
			}
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, dnsHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(dnsConfig)
				if err != nil {
					return err
				}
			case "provider":
				io.WriteString(cmd.Stdout, dnsConfig.Provider+"\n")
			case "username":
				io.WriteString(cmd.Stdout, dnsConfig.Username+"\n")
			case "apiKey":
				io.WriteString(cmd.Stdout, dnsConfig.APIKey+"\n")
			case "apiToken":
				io.WriteString(cmd.Stdout, dnsConfig.APIToken+"\n")
			case "secretKey":
				io.WriteString(cmd.Stdout, dnsConfig.SecretKey+"\n")
			default:
				io.WriteString(cmd.Stderr, dnsHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		case "certmagic":
			b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "certmagic.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			io.WriteString(cmd.Stdout, string(bytes.TrimSpace(b))+"\n")
		default:
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, head)
		}
	}
	switch head {
	case "":
		return fmt.Errorf("key cannot be empty")
	case "port":
		err := os.WriteFile(filepath.Join(cmd.ConfigDir, "port.txt"), []byte(cmd.Value.String), 0644)
		if err != nil {
			return err
		}
	case "cmsdomain":
		err := os.WriteFile(filepath.Join(cmd.ConfigDir, "cmsdomain.txt"), []byte(cmd.Value.String), 0644)
		if err != nil {
			return err
		}
	case "contentdomain":
		err := os.WriteFile(filepath.Join(cmd.ConfigDir, "contentdomain.txt"), []byte(cmd.Value.String), 0644)
		if err != nil {
			return err
		}
	case "imgdomain":
		err := os.WriteFile(filepath.Join(cmd.ConfigDir, "imgdomain.txt"), []byte(cmd.Value.String), 0644)
		if err != nil {
			return err
		}
	case "database":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var databaseConfig DatabaseConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&databaseConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "database.json"), err)
			}
		}
		if databaseConfig.Params == nil {
			databaseConfig.Params = map[string]string{}
		}
		switch tail {
		case "":
			var newDatabaseConfig DatabaseConfig
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&newDatabaseConfig)
			if err != nil {
				return err
			}
			databaseConfig = newDatabaseConfig
		case "dialect":
			databaseConfig.Dialect = cmd.Value.String
		case "filePath":
			databaseConfig.FilePath = cmd.Value.String
		case "user":
			databaseConfig.User = cmd.Value.String
		case "password":
			databaseConfig.Password = cmd.Value.String
		case "host":
			databaseConfig.Host = cmd.Value.String
		case "port":
			databaseConfig.Port = cmd.Value.String
		case "dbName":
			databaseConfig.DBName = cmd.Value.String
		case "params":
			var params map[string]string
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&params)
			if err != nil {
				return err
			}
			databaseConfig.Params = params
		default:
			io.WriteString(cmd.Stderr, databaseHelp)
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
		}
		file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "database.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(databaseConfig)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	case "files":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var filesConfig DatabaseConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&filesConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "files.json"), err)
			}
		}
		if filesConfig.Params == nil {
			filesConfig.Params = map[string]string{}
		}
		switch tail {
		case "":
			var newFilesConfig DatabaseConfig
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&newFilesConfig)
			if err != nil {
				return err
			}
			filesConfig = newFilesConfig
		case "dialect":
			filesConfig.Dialect = cmd.Value.String
		case "filePath":
			filesConfig.FilePath = cmd.Value.String
		case "user":
			filesConfig.User = cmd.Value.String
		case "password":
			filesConfig.Password = cmd.Value.String
		case "host":
			filesConfig.Host = cmd.Value.String
		case "port":
			filesConfig.Port = cmd.Value.String
		case "dbName":
			filesConfig.DBName = cmd.Value.String
		case "params":
			var params map[string]string
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&params)
			if err != nil {
				return err
			}
			filesConfig.Params = params
		default:
			io.WriteString(cmd.Stderr, filesHelp)
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
		}
		file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "files.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(filesConfig)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	case "objects":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "objects.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var objectsConfig ObjectsConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&objectsConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "objects.json"), err)
			}
		}
		switch tail {
		case "":
			var newObjectsConfig ObjectsConfig
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&newObjectsConfig)
			if err != nil {
				return err
			}
			objectsConfig = newObjectsConfig
		case "provider":
			objectsConfig.Provider = cmd.Value.String
		case "filePath":
			objectsConfig.FilePath = cmd.Value.String
		case "endpoint":
			objectsConfig.Endpoint = cmd.Value.String
		case "region":
			objectsConfig.Region = cmd.Value.String
		case "bucket":
			objectsConfig.Bucket = cmd.Value.String
		case "accessKeyID":
			objectsConfig.AccessKeyID = cmd.Value.String
		case "secretAccessKey":
			objectsConfig.SecretAccessKey = cmd.Value.String
		default:
			io.WriteString(cmd.Stderr, objectsHelp)
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
		}
		file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "objects.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(objectsConfig)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	case "captcha":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "captcha.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var captchaConfig CaptchaConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&captchaConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "captcha.json"), err)
			}
		}
		switch tail {
		case "":
			var newCaptchaConfig CaptchaConfig
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&newCaptchaConfig)
			if err != nil {
				return err
			}
			captchaConfig = newCaptchaConfig
		case "verificationURL":
			captchaConfig.VerificationURL = cmd.Value.String
		case "siteKey":
			captchaConfig.SiteKey = cmd.Value.String
		case "secretKey":
			captchaConfig.SecretKey = cmd.Value.String
		default:
			io.WriteString(cmd.Stderr, captchaHelp)
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
		}
	case "dns":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "dns.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var dnsConfig DNSConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&dnsConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "dns.json"), err)
			}
		}
		switch tail {
		case "":
			var newDNSConfig DNSConfig
			decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&newDNSConfig)
			if err != nil {
				return err
			}
			dnsConfig = newDNSConfig
		case "provider":
			dnsConfig.Provider = cmd.Value.String
		case "username":
			dnsConfig.Username = cmd.Value.String
		case "apiKey":
			dnsConfig.APIKey = cmd.Value.String
		case "apiToken":
			dnsConfig.APIToken = cmd.Value.String
		case "secretKey":
			dnsConfig.SecretKey = cmd.Value.String
		default:
			io.WriteString(cmd.Stderr, dnsHelp)
			return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
		}
		file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "dns.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(dnsConfig)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	case "certmagic":
		err := os.WriteFile(filepath.Join(cmd.ConfigDir, "certmagic.txt"), []byte(cmd.Value.String), 0644)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: invalid key %q", cmd.Key.String, head)
	}
	return nil
}

type DatabaseConfig struct {
	Dialect  string            `json:"dialect"`
	FilePath string            `json:"filePath"`
	User     string            `json:"user"`
	Password string            `json:"password"`
	Host     string            `json:"host"`
	Port     string            `json:"port"`
	DBName   string            `json:"dbName"`
	Params   map[string]string `json:"params"`
}

const databaseHelp = `# == database keys == #
# dialect  - Database dialect (possible values: sqlite, postgres, mysql).
# filePath - File path to the sqlite file (if dialect is sqlite).
# user     - Database user
# password - Database password
# host     - Database host
# port     - Database port
# dbName   - Database name
# params   - Database-specific connection parameters
`

const filesHelp = `# == files keys == #
# Choose between using the local filesystem (backed by a plain old directory) or a remote filesystem (backed by a database) to store files.
# dialect  - Database dialect (possible values: sqlite, postgres, mysql -- leave blank if using the local filesystem).
# filePath - Files root directory (if using the local filesystem) or file path to the sqlite file (if using sqlite).
# user     - Database user
# password - Database password
# host     - Database host
# port     - Database port
# dbName   - Database name
# params   - Database-specific connection parameters
`

type ObjectsConfig struct {
	Provider        string `json:"provider"`
	FilePath        string `json:"filePath"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	AccessKeyID     string `json:"accessKeyID"`
	SecretAccessKey string `json:"secretAccessKey"`
}

const objectsHelp = `# == objects keys == #
# Choose between using the local filesystem (backed by a plain old directory) or an S3-compatible provider to store objects. Only applicable if using the remote filesytem (see ` + "`notebrew config files`" + `).
# provider        - Object storage provider (possible values: local, s3)
# filePath        - Objects root directory (if using the local filesystem)
# endpoint        - S3 endpoint.
# region          - S3 region.
# bucket          - S3 bucket.
# accessKeyID     - S3 access key ID.
# secretAccessKey - S3 secret access key.
`

type CaptchaConfig struct {
	VerificationURL string `json:"verificationURL"`
	SiteKey         string `json:"siteKey"`
	SecretKey       string `json:"secretKey"`
}

const captchaHelp = `# == captcha keys == #
# verificationURL - Captcha provider's verification URL to make POST requests to.
# siteKey         - Captcha provider's site key.
# secretKey       - Captcha provider's secret key.
`

type DNSConfig struct {
	Provider  string `json:"provider"`
	Username  string `json:"username"`
	APIKey    string `json:"apiKey"`
	APIToken  string `json:"apiToken"`
	SecretKey string `json:"secretKey"`
}

const dnsHelp = `# == dns keys == #
# provider  - DNS provider (possible values: namecheap, cloudflare, porkbun, godaddy)
# username  - DNS API username   (required by: namecheap)
# apiKey    - DNS API key        (required by: namecheap, porkbun)
# apiToken  - DNS API token      (required by: cloudflare, godaddy)
# secretKey - DNS API secret key (required by: porkbun)
`
