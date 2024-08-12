package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"github.com/stripe/stripe-go/v79"
	portalsession "github.com/stripe/stripe-go/v79/billingportal/session"
	"github.com/stripe/stripe-go/v79/checkout/session"
)

func stripeCheckout(nbrew *nb10.Notebrew, w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	priceID := r.Form.Get("priceID")
	if priceID == "" {
		nbrew.BadRequest(w, r, fmt.Errorf("priceID not provided"))
		return
	}
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	var customerID *string
	if user.CustomerID != "" {
		customerID = &user.CustomerID
	}
	expiresAt := time.Now().Add(30 * time.Minute)
	checkoutSession, err := session.New(&stripe.CheckoutSessionParams{
		Customer:      customerID,
		CustomerEmail: stripe.String(user.Email),
		ExpiresAt:     stripe.Int64(expiresAt.Unix()),
		Mode:          stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(scheme + nbrew.CMSDomain + "/stripe/checkout/success/?sessionID={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(scheme + nbrew.CMSDomain + "/users/profile/"),
	})
	if err != nil {
		var stripeErr *stripe.Error
		if errors.As(err, &stripeErr) {
			fmt.Println(stripeErr.Code)
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	http.Redirect(w, r, checkoutSession.URL, http.StatusSeeOther)
}

func stripeCheckoutSuccess(nbrew *nb10.Notebrew, w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	sessionID := r.Form.Get("sessionID")
	checkoutSession, err := session.Get(sessionID, nil)
	if err != nil {
		var stripeErr *stripe.Error
		if errors.As(err, &stripeErr) {
			fmt.Println(stripeErr.Code)
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	switch nbrew.Dialect {
	case "sqlite", "postgres":
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Debug:   true,
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO customer (customer_id, user_id)" +
				" VALUES ({customerID}, {userID})" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.StringParam("customerID", checkoutSession.Customer.ID),
				sq.UUIDParam("userID", user.UserID),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
	case "mysql":
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Debug:   true,
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO customer (customer_id, user_id)" +
				" VALUES ({customerID}, {userID})" +
				" ON DUPLICATE KEY UPDATE customer_id = customer_id",
			Values: []any{
				sq.StringParam("customerID", checkoutSession.Customer.ID),
				sq.UUIDParam("userID", user.UserID),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
	default:
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Debug:   true,
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO customer (customer_id, user_id)" +
				" VALUES ({customerID}, {userID})",
			Values: []any{
				sq.StringParam("customerID", checkoutSession.Customer.ID),
				sq.UUIDParam("userID", user.UserID),
			},
		})
		if err != nil {
			if nbrew.ErrorCode == nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			errorCode := nbrew.ErrorCode(err)
			if !nb10.IsKeyViolation(nbrew.Dialect, errorCode) {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
	}
	// TODO: set a flash session from=stripe/checkout/success
	http.Redirect(w, r, "/users/profile/", http.StatusSeeOther)
}

func stripePortal(nbrew *nb10.Notebrew, w http.ResponseWriter, r *http.Request, user User) {
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	if user.CustomerID == "" {
		nbrew.BadRequest(w, r, fmt.Errorf("user has no customerID"))
		return
	}
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	billingPortalSession, err := portalsession.New(&stripe.BillingPortalSessionParams{
		Customer:  stripe.String(user.CustomerID),
		ReturnURL: stripe.String(scheme + nbrew.CMSDomain + "/users/profile/"),
	})
	if err != nil {
		var stripeErr *stripe.Error
		if errors.As(err, &stripeErr) {
			fmt.Println(stripeErr.Code)
		}
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	http.Redirect(w, r, billingPortalSession.URL, http.StatusSeeOther)
}
