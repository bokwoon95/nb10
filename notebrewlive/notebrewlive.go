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
	Name         string `json:"name"`
	SiteLimit    int64  `json:"siteLimit"`
	StorageLimit int64  `json:"storageLimit"`
	Price        string `json:"price"`
	PriceID      string `json:"priceID"`
}

type BillingConfig struct {
	StripePublishableKey string `json:"stripePublishableKey"`
	StripeSecretKey      string `json:"stripeSecretKey"`
	StripeWebhookSecret  string `json:"stripeWebhookSecret"`
	Plans                []Plan `json:"plans"`
}

var (
	//go:embed embed
	embedFS   embed.FS
	RuntimeFS fs.FS = embedFS
	//go:embed schema_database.json
	databaseSchemaBytes []byte
)