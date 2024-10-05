package main

import (
	"embed"
	"io/fs"

	"github.com/bokwoon95/nb10"
)

type User struct {
	nb10.User
	CustomerID string
}

type Plan struct {
	Archived     bool            `json:"archived"`
	Name         string          `json:"name"`
	SiteLimit    int64           `json:"siteLimit"`
	StorageLimit int64           `json:"storageLimit"`
	UserFlags    map[string]bool `json:"userFlags"`
	Price        string          `json:"price"`
	PriceID      string          `json:"priceID"`
}

type StripeConfig struct {
	PublishableKey string `json:"publishableKey"`
	SecretKey      string `json:"secretKey"`
	WebhookSecret  string `json:"webhookSecret"`
	Plans          []Plan `json:"plans"`
}

var (
	//go:embed embed
	embedFS   embed.FS
	RuntimeFS fs.FS = embedFS
	//go:embed schema_database.json
	databaseSchemaBytes []byte
)
