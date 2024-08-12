package main

type BillingConfig struct {
	StripePublishableKey string `json:"stripePublishableKey"`
	StripeSecretKey      string `json:"stripeSecretKey"`
	Plans                []Plan `json:"plans"`
}

type Plan struct {
	Name         string `json:"name"`
	SiteLimit    int64  `json:"siteLimit"`
	StorageLimit int64  `json:"storageLimit"`
	Price        string `json:"price"`
	PriceID      string `json:"priceID"`
}
