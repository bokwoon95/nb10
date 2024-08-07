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

const configxHelp = `Keys:
  notebrew configx stripe # (json) Stripe configuration.
  notebrew configx smtp   # (json) SMTP configuration.
`

type ConfigxCmd struct {
	ConfigDir string
	Stdout    io.Writer
	Stderr    io.Writer
	Key       sql.NullString
	Value     sql.NullString
}

func ConfigxCommand(configDir string, args ...string) (*ConfigxCmd, error) {
	var cmd ConfigxCmd
	cmd.ConfigDir = configDir
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		io.WriteString(flagset.Output(), configxHelp)
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

func (cmd *ConfigxCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	if !cmd.Key.Valid {
		io.WriteString(cmd.Stderr, configxHelp)
		return nil
	}
	if cmd.Value.String == "nil" {
		cmd.Value.String = ""
	}
	head, tail, _ := strings.Cut(cmd.Key.String, ".")
	switch head {
	case "":
		return fmt.Errorf("key cannot be empty")
	case "stripe":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "stripe.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var stripeConfig StripeConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&stripeConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "stripe.json"), err)
			}
		}
		if cmd.Value.Valid {
			switch tail {
			case "":
				var newStripeConfig StripeConfig
				if cmd.Value.String != "" {
					decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
					decoder.DisallowUnknownFields()
					err := decoder.Decode(&newStripeConfig)
					if err != nil {
						return err
					}
				}
				stripeConfig = newStripeConfig
			case "publishableKey":
				stripeConfig.PublishableKey = cmd.Value.String
			case "secretKey":
				stripeConfig.SecretKey = cmd.Value.String
			default:
				io.WriteString(cmd.Stderr, stripeHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
			file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "stripe.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(stripeConfig)
			if err != nil {
				return err
			}
			err = file.Close()
			if err != nil {
				return err
			}
		} else {
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, stripeHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(stripeConfig)
				if err != nil {
					return err
				}
			case "publishableKey":
				io.WriteString(cmd.Stdout, stripeConfig.PublishableKey+"\n")
			case "secretKey":
				io.WriteString(cmd.Stdout, stripeConfig.SecretKey+"\n")
			default:
				io.WriteString(cmd.Stderr, stripeHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		}
	case "smtp":
		b, err := os.ReadFile(filepath.Join(cmd.ConfigDir, "smtp.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var smtpConfig SMTPConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&smtpConfig)
			if err != nil && tail != "" {
				return fmt.Errorf("%s: %w", filepath.Join(cmd.ConfigDir, "smtp.json"), err)
			}
		}
		if cmd.Value.Valid {
			switch tail {
			case "":
				var newSMTPConfig SMTPConfig
				if cmd.Value.String != "" {
					decoder := json.NewDecoder(strings.NewReader(cmd.Value.String))
					decoder.DisallowUnknownFields()
					err := decoder.Decode(&newSMTPConfig)
					if err != nil {
						return err
					}
				}
				smtpConfig = newSMTPConfig
			case "username":
				smtpConfig.Username = cmd.Value.String
			case "password":
				smtpConfig.Password = cmd.Value.String
			case "host":
				smtpConfig.Host = cmd.Value.String
			case "port":
				smtpConfig.Port = cmd.Value.String
			case "mailFrom":
				smtpConfig.MailFrom = cmd.Value.String
			default:
				io.WriteString(cmd.Stderr, smtpHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
			file, err := os.OpenFile(filepath.Join(cmd.ConfigDir, "smtp.json"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(smtpConfig)
			if err != nil {
				return err
			}
			err = file.Close()
			if err != nil {
				return err
			}
		} else {
			switch tail {
			case "":
				io.WriteString(cmd.Stderr, smtpHelp)
				encoder := json.NewEncoder(cmd.Stdout)
				encoder.SetIndent("", "  ")
				err := encoder.Encode(smtpConfig)
				if err != nil {
					return err
				}
			case "username":
				io.WriteString(cmd.Stdout, smtpConfig.Username+"\n")
			case "password":
				io.WriteString(cmd.Stdout, smtpConfig.Password+"\n")
			case "host":
				io.WriteString(cmd.Stdout, smtpConfig.Host+"\n")
			case "port":
				io.WriteString(cmd.Stdout, smtpConfig.Port+"\n")
			case "mailFrom":
				io.WriteString(cmd.Stdout, smtpConfig.MailFrom+"\n")
			default:
				io.WriteString(cmd.Stderr, smtpHelp)
				return fmt.Errorf("%s: invalid key %q", cmd.Key.String, tail)
			}
		}
	default:
		io.WriteString(cmd.Stderr, configxHelp)
		return fmt.Errorf("%s: invalid key %q", cmd.Key.String, head)
	}
	return nil
}

type StripeConfig struct {
	PublishableKey string `json:"publishableKey"`
	SecretKey      string `json:"secretKey"`
}

const stripeHelp = `# == stripe keys == #
# publishableKey  - Stripe publishable key.
# secretKey       - Stripe secret key.
`

type SMTPConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	MailFrom string `json:"mailFrom"`
}

const smtpHelp = `# == smtp keys == #
# username - SMTP username.
# password - SMTP password.
# host     - SMTP host.
# port     - SMTP port.
# mailFrom - SMTP MAIL FROM address
`
