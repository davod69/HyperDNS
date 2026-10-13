package database

import (
	"errors"
	"fmt"
	"math"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

var (
	ErrCommerceNotFound             = errors.New("commerce record not found")
	ErrCommerceSchemaMissing        = errors.New("commerce schema is not initialized")
	ErrCommerceEmailExists          = errors.New("a customer with this email already exists")
	ErrCommercePlanDisabled         = errors.New("commerce plan is disabled")
	ErrCommerceCustomerSuspended    = errors.New("commerce customer is suspended")
	ErrCommerceOrderNotPending      = errors.New("commerce order is not pending")
	ErrCommerceOrderAlreadyPaid     = errors.New("commerce order has already been paid")
	ErrCommercePaymentDuplicate     = errors.New("payment reference or event was already used")
	ErrCommerceInvalidRecord        = errors.New("invalid commerce record")
)

type CommerceCustomerStatus string

const (
	CommerceCustomerActive    CommerceCustomerStatus = "active"
	CommerceCustomerSuspended CommerceCustomerStatus = "suspended"
)

type CommerceOrderStatus string

const (
	CommerceOrderPending   CommerceOrderStatus = "pending"
	CommerceOrderPaid      CommerceOrderStatus = "paid"
	CommerceOrderFulfilled CommerceOrderStatus = "fulfilled"
	CommerceOrderCancelled CommerceOrderStatus = "cancelled"
	CommerceOrderRefunded  CommerceOrderStatus = "refunded"
)

type CommercePaymentStatus string

const (
	CommercePaymentConfirmed CommercePaymentStatus = "confirmed"
)

// CommerceCustomer is the safe, serializable customer profile. Password hashes
// and encrypted database fields deliberately live in a separate storage type.
type CommerceCustomer struct {
	ID          string                `json:"id"`
	Email       string                `json:"email"`
	DisplayName string                `json:"display_name"`
	Status      CommerceCustomerStatus `json:"status"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

// CommercePlan is a reusable product definition. PriceMinor is an integer in
// the currency's minor unit (for example, cents), never a floating-point price.
// A zero TrafficLimitGB means unlimited traffic. Lifetime plans use Lifetime=true.
type CommercePlan struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	Currency          string    `json:"currency"`
	PriceMinor        int64     `json:"price_minor"`
	DurationDays      int       `json:"duration_days"`
	Lifetime          bool      `json:"lifetime"`
	TrafficLimitGB    float64   `json:"traffic_limit_gb"`
	TrafficResetCycle string    `json:"traffic_reset_cycle"`
	Policies          []string  `json:"policies"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CommerceOrder snapshots the relevant plan fields at purchase time. Editing a
// plan later must never silently change the price or allowance of an existing order.
type CommerceOrder struct {
	ID                string             `json:"id"`
	CustomerID        string             `json:"customer_id"`
	PlanID            string             `json:"plan_id"`
	PlanName          string             `json:"plan_name"`
	Currency          string             `json:"currency"`
	AmountMinor       int64              `json:"amount_minor"`
	DurationDays      int                `json:"duration_days"`
	Lifetime          bool               `json:"lifetime"`
	TrafficLimitGB    float64            `json:"traffic_limit_gb"`
	TrafficResetCycle string             `json:"traffic_reset_cycle"`
	Policies          []string           `json:"policies"`
	Status            CommerceOrderStatus `json:"status"`
	ClientID          string             `json:"client_id,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	PaidAt            time.Time          `json:"paid_at,omitempty"`
	FulfilledAt       time.Time          `json:"fulfilled_at,omitempty"`
}

// CommercePayment stores transaction metadata only. Never put card numbers,
// provider secrets, or an unverified raw webhook body in this record.
type CommercePayment struct {
	ID                string               `json:"id"`
	OrderID           string               `json:"order_id"`
	Provider          string               `json:"provider"`
	ProviderPaymentID string               `json:"provider_payment_id"`
	AmountMinor       int64                `json:"amount_minor"`
	Currency          string               `json:"currency"`
	Status            CommercePaymentStatus `json:"status"`
	CreatedAt         time.Time            `json:"created_at"`
	ConfirmedAt       time.Time            `json:"confirmed_at"`
}

type storedCommerceCustomer struct {
	ID             string                `json:"id"`
	EmailEnc       string                `json:"email_enc"`
	EmailIndex     string                `json:"email_index"`
	DisplayNameEnc string                `json:"display_name_enc,omitempty"`
	PasswordHash   string                `json:"password_hash"`
	Status         CommerceCustomerStatus `json:"status"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type commercePaymentEvent struct {
	OrderID           string    `json:"order_id"`
	PaymentID         string    `json:"payment_id"`
	ProviderPaymentID string    `json:"provider_payment_id"`
	AmountMinor       int64     `json:"amount_minor"`
	Currency          string    `json:"currency"`
	CreatedAt         time.Time `json:"created_at"`
}

var commerceCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

func normalizeCommerceEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 254 {
		return "", fmt.Errorf("%w: email is empty or too long", ErrCommerceInvalidRecord)
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Address != raw || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("%w: email must be a single address without a display name", ErrCommerceInvalidRecord)
	}
	return strings.ToLower(parsed.Address), nil
}

func validateCommerceCustomerStatus(status CommerceCustomerStatus) error {
	if status != CommerceCustomerActive && status != CommerceCustomerSuspended {
		return fmt.Errorf("%w: unsupported customer status %q", ErrCommerceInvalidRecord, status)
	}
	return nil
}

func normalizeAndValidateCommercePlan(plan CommercePlan) (CommercePlan, error) {
	plan.ID = strings.TrimSpace(plan.ID)
	plan.Name = strings.TrimSpace(plan.Name)
	plan.Description = strings.TrimSpace(plan.Description)
	plan.Currency = strings.TrimSpace(plan.Currency)
	plan.TrafficResetCycle = strings.ToLower(strings.TrimSpace(plan.TrafficResetCycle))

	if plan.ID == "" || len(plan.ID) > 128 {
		return plan, fmt.Errorf("%w: plan ID is required", ErrCommerceInvalidRecord)
	}
	if plan.Name == "" || len(plan.Name) > 120 {
		return plan, fmt.Errorf("%w: plan name must contain 1 to 120 characters", ErrCommerceInvalidRecord)
	}
	if len(plan.Description) > 3000 {
		return plan, fmt.Errorf("%w: plan description is too long", ErrCommerceInvalidRecord)
	}
	if !commerceCurrencyPattern.MatchString(plan.Currency) {
		return plan, fmt.Errorf("%w: currency must be a three-letter uppercase code", ErrCommerceInvalidRecord)
	}
	if plan.PriceMinor <= 0 {
		return plan, fmt.Errorf("%w: price_minor must be greater than zero", ErrCommerceInvalidRecord)
	}
	if plan.Lifetime {
		plan.DurationDays = 0
	} else if plan.DurationDays <= 0 || plan.DurationDays > 36500 {
		return plan, fmt.Errorf("%w: duration_days must be between 1 and 36500 for a non-lifetime plan", ErrCommerceInvalidRecord)
	}
	if math.IsNaN(plan.TrafficLimitGB) || math.IsInf(plan.TrafficLimitGB, 0) || plan.TrafficLimitGB < 0 {
		return plan, fmt.Errorf("%w: traffic_limit_gb must be finite and non-negative", ErrCommerceInvalidRecord)
	}
	switch plan.TrafficResetCycle {
	case "", "daily", "weekly", "monthly":
	default:
		return plan, fmt.Errorf("%w: traffic_reset_cycle must be empty, daily, weekly or monthly", ErrCommerceInvalidRecord)
	}
	if plan.TrafficLimitGB == 0 && plan.TrafficResetCycle != "" {
		return plan, fmt.Errorf("%w: an unlimited traffic plan cannot have a traffic reset cycle", ErrCommerceInvalidRecord)
	}
	if plan.Policies == nil {
		plan.Policies = []string{}
	}
	for i, policy := range plan.Policies {
		plan.Policies[i] = strings.TrimSpace(policy)
		if plan.Policies[i] == "" || len(plan.Policies[i]) > 128 {
			return plan, fmt.Errorf("%w: policies must be non-empty identifiers no longer than 128 characters", ErrCommerceInvalidRecord)
		}
	}
	return plan, nil
}
