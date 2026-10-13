package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketSalesCustomers          = []byte("sales_customers")
	bucketSalesCustomerEmail      = []byte("sales_customer_email")
	bucketSalesCustomerTelegram   = []byte("sales_customer_telegram")
	bucketSalesPlans               = []byte("sales_plans")
	bucketSalesOrders              = []byte("sales_orders")
	bucketSalesOrderIdempotency    = []byte("sales_order_idempotency")
	bucketSalesOrderCustomer       = []byte("sales_order_customer")
	bucketSalesPayments            = []byte("sales_payments")
	bucketSalesPaymentReference    = []byte("sales_payment_reference")
	bucketSalesSubscriptions       = []byte("sales_subscriptions")
	bucketSalesSubscriptionCustomer = []byte("sales_subscription_customer")
	bucketSalesAuditEvents         = []byte("sales_audit_events")
)

const commercialEnvelopePrefix = "hdns:commerce:v1:"

var (
	ErrCommerceRecordNotFound = errors.New("commercial record not found")
	ErrCommerceRecordExists   = errors.New("commercial record already exists")
	ErrCommerceEmailTaken     = errors.New("customer email is already registered")
	ErrCommerceTelegramTaken  = errors.New("Telegram account is already linked")
	ErrCommerceIdempotencyKey = errors.New("idempotency key has already been used")
	ErrCommercePaymentRef     = errors.New("payment provider reference is already registered")
	ErrCommerceInvalidRecord  = errors.New("invalid commercial record")
	ErrCommerceTransition     = errors.New("invalid commercial status transition")
	ErrCommerceForeignKey     = errors.New("commercial record references a missing record")
)

type CommerceCustomer struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	DisplayName    string    `json:"display_name"`
	PasswordHash   string    `json:"password_hash"`
	TelegramUserID int64     `json:"telegram_user_id,omitempty"`
	EmailVerified  bool      `json:"email_verified"`
	Disabled       bool      `json:"disabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SalesPlan stores money as integer minor units. DurationDays == 0 means
// lifetime. A purchased subscription keeps a snapshot so future edits to a
// plan never rewrite benefits that were already sold.
type SalesPlan struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	PriceMinor        int64     `json:"price_minor"`
	Currency          string    `json:"currency"`
	DurationDays      int       `json:"duration_days"`
	TrafficLimitGB    float64   `json:"traffic_limit_gb"`
	TrafficResetCycle string    `json:"traffic_reset_cycle"`
	PolicyIDs         []string  `json:"policy_ids"`
	Active            bool      `json:"active"`
	SortOrder         int       `json:"sort_order"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const (
	SalesOrderPending   = "pending"
	SalesOrderPaid      = "paid"
	SalesOrderFailed    = "failed"
	SalesOrderCancelled = "cancelled"
	SalesOrderExpired   = "expired"
	SalesOrderRefunded  = "refunded"

	SalesPaymentPending   = "pending"
	SalesPaymentSucceeded = "succeeded"
	SalesPaymentFailed    = "failed"
	SalesPaymentCancelled = "cancelled"
	SalesPaymentRefunded  = "refunded"

	CustomerSubscriptionPending   = "pending"
	CustomerSubscriptionActive    = "active"
	CustomerSubscriptionSuspended = "suspended"
	CustomerSubscriptionExpired   = "expired"
	CustomerSubscriptionCancelled = "cancelled"
)

type SalesOrder struct {
	ID             string    `json:"id"`
	CustomerID     string    `json:"customer_id"`
	PlanID         string    `json:"plan_id"`
	PlanName       string    `json:"plan_name"`
	PlanSnapshot   SalesPlan `json:"plan_snapshot"`
	AmountMinor    int64     `json:"amount_minor"`
	Currency       string    `json:"currency"`
	Status         string    `json:"status"`
	IdempotencyKey string    `json:"idempotency_key,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	PaidAt         time.Time `json:"paid_at,omitempty"`
}

type SalesPayment struct {
	ID                string    `json:"id"`
	OrderID           string    `json:"order_id"`
	CustomerID        string    `json:"customer_id"`
	Provider          string    `json:"provider"`
	ProviderReference string    `json:"provider_reference,omitempty"`
	AmountMinor       int64     `json:"amount_minor"`
	Currency          string    `json:"currency"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	VerifiedAt        time.Time `json:"verified_at,omitempty"`
}

type CustomerSubscription struct {
	ID           string    `json:"id"`
	CustomerID   string    `json:"customer_id"`
	PlanID       string    `json:"plan_id"`
	OrderID      string    `json:"order_id"`
	ClientID     string    `json:"client_id,omitempty"`
	PlanSnapshot SalesPlan `json:"plan_snapshot"`
	Status       string    `json:"status"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CommercialAuditEvent struct {
	ID         string            `json:"id"`
	ActorType  string            `json:"actor_type"`
	ActorID    string            `json:"actor_id,omitempty"`
	Action     string            `json:"action"`
	EntityType string            `json:"entity_type"`
	EntityID   string            `json:"entity_id,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

func (db *DB) sealCommercialRecord(value any) ([]byte, error) {
	if db == nil || db.bolt == nil || db.cipher == nil {
		return nil, errors.New("commercial storage requires an open database and master key")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode commercial record: %w", err)
	}
	sealed, err := db.cipher.EncryptString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("encrypt commercial record: %w", err)
	}
	return append([]byte(commercialEnvelopePrefix), []byte(sealed)...), nil
}

func (db *DB) openCommercialRecord(raw []byte, target any) error {
	if db == nil || db.bolt == nil || db.cipher == nil {
		return errors.New("commercial storage requires an open database and master key")
	}
	if !bytes.HasPrefix(raw, []byte(commercialEnvelopePrefix)) {
		return errors.New("commercial record is not encrypted or uses an unknown format")
	}
	plain, err := db.cipher.DecryptString(string(raw[len(commercialEnvelopePrefix):]))
	if err != nil {
		return fmt.Errorf("decrypt commercial record (wrong master key?): %w", err)
	}
	if err := json.Unmarshal([]byte(plain), target); err != nil {
		return fmt.Errorf("decode commercial record: %w", err)
	}
	return nil
}

func readCommercialTx(db *DB, tx *bolt.Tx, bucketName []byte, key string, target any) (bool, error) {
	b := tx.Bucket(bucketName)
	if b == nil {
		return false, nil
	}
	raw := b.Get([]byte(key))
	if raw == nil {
		return false, nil
	}
	if err := db.openCommercialRecord(raw, target); err != nil {
		return false, err
	}
	return true, nil
}

func writeCommercialTx(db *DB, tx *bolt.Tx, bucketName []byte, key string, value any) error {
	b := tx.Bucket(bucketName)
	if b == nil {
		return fmt.Errorf("commercial bucket %q is missing", bucketName)
	}
	raw, err := db.sealCommercialRecord(value)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func getCommercialRecord[T any](db *DB, bucketName []byte, key string) (*T, error) {
	if db == nil || db.bolt == nil {
		return nil, errors.New("database is not open")
	}
	var result T
	err := db.bolt.View(func(tx *bolt.Tx) error {
		found, err := readCommercialTx(db, tx, bucketName, key, &result)
		if err != nil {
			return err
		}
		if !found {
			return ErrCommerceRecordNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func normaliseCommerceEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 254 {
		return "", fmt.Errorf("%w: a valid email address is required", ErrCommerceInvalidRecord)
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || strings.ContainsAny(email, "\r\n\t ") {
		return "", fmt.Errorf("%w: invalid email address", ErrCommerceInvalidRecord)
	}
	return email, nil
}

func normaliseCommerceCurrency(raw string) (string, error) {
	currency := strings.ToUpper(strings.TrimSpace(raw))
	if len(currency) < 3 || len(currency) > 8 {
		return "", fmt.Errorf("%w: currency must be a 3-8 character code", ErrCommerceInvalidRecord)
	}
	for _, r := range currency {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "", fmt.Errorf("%w: invalid currency code", ErrCommerceInvalidRecord)
		}
	}
	return currency, nil
}

func validateQuotaCycle(cycle string) error {
	switch cycle {
	case "", "daily", "weekly", "monthly":
		return nil
	default:
		return fmt.Errorf("%w: quota reset cycle must be empty, daily, weekly or monthly", ErrCommerceInvalidRecord)
	}
}

func validateSalesPlan(p *SalesPlan) error {
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)
	currency, err := normaliseCommerceCurrency(p.Currency)
	if err != nil {
		return err
	}
	p.Currency = currency
	if p.ID == "" || p.Name == "" {
		return fmt.Errorf("%w: plan ID and name are required", ErrCommerceInvalidRecord)
	}
	if p.PriceMinor < 0 || p.DurationDays < 0 || p.TrafficLimitGB < 0 ||
		math.IsNaN(p.TrafficLimitGB) || math.IsInf(p.TrafficLimitGB, 0) {
		return fmt.Errorf("%w: plan price, duration and quota cannot be negative or non-finite", ErrCommerceInvalidRecord)
	}
	if err := validateQuotaCycle(p.TrafficResetCycle); err != nil {
		return err
	}
	if p.PolicyIDs == nil {
		p.PolicyIDs = []string{}
	}
	return nil
}

func validOrderStatus(status string) bool {
	switch status {
	case SalesOrderPending, SalesOrderPaid, SalesOrderFailed, SalesOrderCancelled, SalesOrderExpired, SalesOrderRefunded:
		return true
	default:
		return false
	}
}

func canTransitionOrder(from, to string) bool {
	if from == to { return true }
	switch from {
	case SalesOrderPending:
		return to == SalesOrderPaid || to == SalesOrderFailed || to == SalesOrderCancelled || to == SalesOrderExpired
	case SalesOrderPaid:
		return to == SalesOrderRefunded
	default:
		return false
	}
}

func validPaymentStatus(status string) bool {
	switch status {
	case SalesPaymentPending, SalesPaymentSucceeded, SalesPaymentFailed, SalesPaymentCancelled, SalesPaymentRefunded:
		return true
	default:
		return false
	}
}

func canTransitionPayment(from, to string) bool {
	if from == to { return true }
	switch from {
	case SalesPaymentPending:
		return to == SalesPaymentSucceeded || to == SalesPaymentFailed || to == SalesPaymentCancelled
	case SalesPaymentSucceeded:
		return to == SalesPaymentRefunded
	default:
		return false
	}
}

func validCustomerSubscriptionStatus(status string) bool {
	switch status {
	case CustomerSubscriptionPending, CustomerSubscriptionActive, CustomerSubscriptionSuspended, CustomerSubscriptionExpired, CustomerSubscriptionCancelled:
		return true
	default:
		return false
	}
}

func canTransitionCustomerSubscription(from, to string) bool {
	if from == to { return true }
	switch from {
	case CustomerSubscriptionPending:
		return to == CustomerSubscriptionActive || to == CustomerSubscriptionCancelled || to == CustomerSubscriptionExpired
	case CustomerSubscriptionActive:
		return to == CustomerSubscriptionSuspended || to == CustomerSubscriptionCancelled || to == CustomerSubscriptionExpired
	case CustomerSubscriptionSuspended:
		return to == CustomerSubscriptionActive || to == CustomerSubscriptionCancelled || to == CustomerSubscriptionExpired
	default:
		return false
	}
}

func (db *DB) CreateCommerceCustomer(c CommerceCustomer) (CommerceCustomer, error) {
	return db.saveCommerceCustomer(c, true)
}
func (db *DB) SaveCommerceCustomer(c CommerceCustomer) (CommerceCustomer, error) {
	return db.saveCommerceCustomer(c, false)
}

func (db *DB) saveCommerceCustomer(c CommerceCustomer, createOnly bool) (CommerceCustomer, error) {
	if db == nil || db.bolt == nil || db.cipher == nil {
		return c, errors.New("commercial customer storage requires an open database and master key")
	}
	var err error
	c.Email, err = normaliseCommerceEmail(c.Email)
	if err != nil { return c, err }
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	c.PasswordHash = strings.TrimSpace(c.PasswordHash)
	if c.DisplayName == "" || c.PasswordHash == "" || c.TelegramUserID < 0 {
		return c, fmt.Errorf("%w: display name and password hash are required; Telegram ID cannot be negative", ErrCommerceInvalidRecord)
	}
	if c.ID == "" { c.ID = GenerateUUID() }
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() { c.CreatedAt = now }
	c.UpdatedAt = now
	emailKey := db.cipher.BlindIndex("sales-email:" + c.Email)
	telegramKey := ""
	if c.TelegramUserID > 0 { telegramKey = strconv.FormatInt(c.TelegramUserID, 10) }

	err = db.bolt.Update(func(tx *bolt.Tx) error {
		customers := tx.Bucket(bucketSalesCustomers)
		emails := tx.Bucket(bucketSalesCustomerEmail)
		telegrams := tx.Bucket(bucketSalesCustomerTelegram)
		if customers == nil || emails == nil || telegrams == nil { return errors.New("commercial customer buckets are missing") }
		var old CommerceCustomer
		oldRaw := customers.Get([]byte(c.ID))
		exists := oldRaw != nil
		if exists {
			if err := db.openCommercialRecord(oldRaw, &old); err != nil { return err }
			if createOnly { return ErrCommerceRecordExists }
			c.CreatedAt = old.CreatedAt
		}
		if owner := emails.Get([]byte(emailKey)); owner != nil && string(owner) != c.ID { return ErrCommerceEmailTaken }
		if telegramKey != "" {
			if owner := telegrams.Get([]byte(telegramKey)); owner != nil && string(owner) != c.ID { return ErrCommerceTelegramTaken }
		}
		if exists {
			oldEmailKey := db.cipher.BlindIndex("sales-email:" + old.Email)
			if oldEmailKey != emailKey {
				if err := emails.Delete([]byte(oldEmailKey)); err != nil { return err }
			}
			if old.TelegramUserID > 0 && old.TelegramUserID != c.TelegramUserID {
				if err := telegrams.Delete([]byte(strconv.FormatInt(old.TelegramUserID, 10))); err != nil { return err }
			}
		}
		raw, err := db.sealCommercialRecord(c)
		if err != nil { return err }
		if err := customers.Put([]byte(c.ID), raw); err != nil { return err }
		if err := emails.Put([]byte(emailKey), []byte(c.ID)); err != nil { return err }
		if telegramKey != "" {
			if err := telegrams.Put([]byte(telegramKey), []byte(c.ID)); err != nil { return err }
		}
		return nil
	})
	return c, err
}

func (db *DB) GetCommerceCustomer(id string) (*CommerceCustomer, error) {
	return getCommercialRecord[CommerceCustomer](db, bucketSalesCustomers, id)
}

func (db *DB) GetCommerceCustomerByEmail(email string) (*CommerceCustomer, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return nil, errors.New("commercial customer storage requires an open database and master key") }
	normalised, err := normaliseCommerceEmail(email)
	if err != nil { return nil, err }
	var id string
	err = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesCustomerEmail)
		if b == nil { return ErrCommerceRecordNotFound }
		value := b.Get([]byte(db.cipher.BlindIndex("sales-email:" + normalised)))
		if value == nil { return ErrCommerceRecordNotFound }
		id = string(value)
		return nil
	})
	if err != nil { return nil, err }
	customer, err := db.GetCommerceCustomer(id)
	if err != nil { return nil, err }
	if customer.Email != normalised { return nil, errors.New("customer email index does not match encrypted record") }
	return customer, nil
}

func (db *DB) GetCommerceCustomerByTelegramID(telegramID int64) (*CommerceCustomer, error) {
	if telegramID <= 0 { return nil, fmt.Errorf("%w: Telegram ID must be positive", ErrCommerceInvalidRecord) }
	var id string
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesCustomerTelegram)
		if b == nil { return ErrCommerceRecordNotFound }
		value := b.Get([]byte(strconv.FormatInt(telegramID, 10)))
		if value == nil { return ErrCommerceRecordNotFound }
		id = string(value)
		return nil
	})
	if err != nil { return nil, err }
	return db.GetCommerceCustomer(id)
}

func (db *DB) ListCommerceCustomers(limit int) ([]CommerceCustomer, error) {
	return listCommercialRecords[CommerceCustomer](db, bucketSalesCustomers, limit, func(a, b CommerceCustomer) bool {
		return a.CreatedAt.After(b.CreatedAt)
	})
}

func listCommercialRecords[T any](db *DB, bucketName []byte, limit int, less func(T, T) bool) ([]T, error) {
	if db == nil || db.bolt == nil { return nil, errors.New("database is not open") }
	if limit <= 0 { limit = 50 }; if limit > 500 { limit = 500 }
	values := make([]T, 0)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil { return nil }
		return b.ForEach(func(_, raw []byte) error {
			var item T
			if err := db.openCommercialRecord(raw, &item); err != nil { return err }
			values = append(values, item)
			return nil
		})
	})
	if err != nil { return nil, err }
	sort.Slice(values, func(i, j int) bool { return less(values[i], values[j]) })
	if len(values) > limit { values = values[:limit] }
	return values, nil
}

func (db *DB) CreateSalesPlan(p SalesPlan) (SalesPlan, error) { return db.saveSalesPlan(p, true) }
func (db *DB) SaveSalesPlan(p SalesPlan) (SalesPlan, error) { return db.saveSalesPlan(p, false) }

func (db *DB) saveSalesPlan(p SalesPlan, createOnly bool) (SalesPlan, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return p, errors.New("sales plan storage requires an open database and master key") }
	if p.ID == "" { p.ID = GenerateUUID() }
	if err := validateSalesPlan(&p); err != nil { return p, err }
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() { p.CreatedAt = now }
	p.UpdatedAt = now
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesPlans)
		if b == nil { return errors.New("sales plan bucket is missing") }
		var old SalesPlan
		exists, err := readCommercialTx(db, tx, bucketSalesPlans, p.ID, &old)
		if err != nil { return err }
		if exists {
			if createOnly { return ErrCommerceRecordExists }
			p.CreatedAt = old.CreatedAt
		}
		return writeCommercialTx(db, tx, bucketSalesPlans, p.ID, p)
	})
	return p, err
}

func (db *DB) GetSalesPlan(id string) (*SalesPlan, error) {
	return getCommercialRecord[SalesPlan](db, bucketSalesPlans, id)
}
func (db *DB) ListSalesPlans(activeOnly bool) ([]SalesPlan, error) {
	plans, err := listCommercialRecords[SalesPlan](db, bucketSalesPlans, 500, func(a, b SalesPlan) bool {
		if a.SortOrder != b.SortOrder { return a.SortOrder < b.SortOrder }
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	if err != nil { return nil, err }
	if !activeOnly { return plans, nil }
	active := plans[:0]
	for _, p := range plans { if p.Active { active = append(active, p) } }
	return active, nil
}

func (db *DB) SaveSalesOrder(o SalesOrder) (SalesOrder, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return o, errors.New("sales order storage requires an open database and master key") }
	if o.ID == "" { o.ID = GenerateUUID() }
	o.CustomerID, o.PlanID, o.PlanName = strings.TrimSpace(o.CustomerID), strings.TrimSpace(o.PlanID), strings.TrimSpace(o.PlanName)
	var err error
	o.Currency, err = normaliseCommerceCurrency(o.Currency)
	if err != nil { return o, err }
	if o.CustomerID == "" || o.PlanID == "" || o.AmountMinor < 0 { return o, fmt.Errorf("%w: order customer, plan and a non-negative amount are required", ErrCommerceInvalidRecord) }
	if o.Status == "" { o.Status = SalesOrderPending }
	if !validOrderStatus(o.Status) { return o, fmt.Errorf("%w: unknown order status", ErrCommerceInvalidRecord) }
	o.IdempotencyKey = strings.TrimSpace(o.IdempotencyKey)
	if len(o.IdempotencyKey) > 200 { return o, fmt.Errorf("%w: idempotency key is too long", ErrCommerceInvalidRecord) }
	if o.PlanName == "" {
		p, e := db.GetSalesPlan(o.PlanID)
		if e != nil { return o, fmt.Errorf("%w: plan: %v", ErrCommerceForeignKey, e) }
		o.PlanName = p.Name
	}
	now := time.Now().UTC()
	if o.CreatedAt.IsZero() { o.CreatedAt = now }
	o.UpdatedAt = now
	idemKey := ""
	if o.IdempotencyKey != "" { idemKey = db.cipher.BlindIndex("sales-order:" + o.CustomerID + ":" + o.IdempotencyKey) }
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		orders, idem, byCustomer := tx.Bucket(bucketSalesOrders), tx.Bucket(bucketSalesOrderIdempotency), tx.Bucket(bucketSalesOrderCustomer)
		if orders == nil || idem == nil || byCustomer == nil { return errors.New("sales order buckets are missing") }
		var customer CommerceCustomer
		found, err := readCommercialTx(db, tx, bucketSalesCustomers, o.CustomerID, &customer)
		if err != nil { return err }
		if !found || customer.Disabled { return fmt.Errorf("%w: customer does not exist or is disabled", ErrCommerceForeignKey) }
		var plan SalesPlan
		found, err = readCommercialTx(db, tx, bucketSalesPlans, o.PlanID, &plan)
		if err != nil { return err }; if !found { return ErrCommerceForeignKey }
		var old SalesOrder
		oldRaw := orders.Get([]byte(o.ID)); exists := oldRaw != nil
		if exists {
			if err := db.openCommercialRecord(oldRaw, &old); err != nil { return err }
			if old.CustomerID != o.CustomerID || old.PlanID != o.PlanID || old.AmountMinor != o.AmountMinor || old.Currency != o.Currency || old.PlanName != o.PlanName || old.IdempotencyKey != o.IdempotencyKey {
				return fmt.Errorf("%w: order terms are immutable", ErrCommerceInvalidRecord)
			}
			if !canTransitionOrder(old.Status, o.Status) { return ErrCommerceTransition }
			o.CreatedAt = old.CreatedAt
			if old.PlanSnapshot.ID == "" { o.PlanSnapshot = plan } else { o.PlanSnapshot = old.PlanSnapshot }
		} else {
			if !plan.Active { return fmt.Errorf("%w: plan is not available for purchase", ErrCommerceInvalidRecord) }
			if o.AmountMinor != plan.PriceMinor || o.Currency != plan.Currency || o.PlanName != plan.Name {
				return fmt.Errorf("%w: order price, currency and name must match the current plan", ErrCommerceInvalidRecord)
			}
			o.PlanSnapshot = plan
		}
		if o.PlanSnapshot.ID != o.PlanID || o.PlanSnapshot.PriceMinor != o.AmountMinor || o.PlanSnapshot.Currency != o.Currency || o.PlanSnapshot.Name != o.PlanName {
			return fmt.Errorf("%w: plan snapshot does not match immutable order terms", ErrCommerceInvalidRecord)
		}
		if idemKey != "" {
			if owner := idem.Get([]byte(idemKey)); owner != nil && string(owner) != o.ID { return ErrCommerceIdempotencyKey }
		}
		raw, err := db.sealCommercialRecord(o); if err != nil { return err }
		if err := orders.Put([]byte(o.ID), raw); err != nil { return err }
		if idemKey != "" { if err := idem.Put([]byte(idemKey), []byte(o.ID)); err != nil { return err } }
		return byCustomer.Put([]byte(o.CustomerID+":"+o.ID), []byte(o.ID))
	})
	return o, err
}

func (db *DB) GetSalesOrder(id string) (*SalesOrder, error) {
	return getCommercialRecord[SalesOrder](db, bucketSalesOrders, id)
}
func (db *DB) GetSalesOrderByIdempotencyKey(customerID, key string) (*SalesOrder, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return nil, errors.New("sales order storage requires an open database and master key") }
	customerID, key = strings.TrimSpace(customerID), strings.TrimSpace(key)
	if customerID == "" || key == "" { return nil, fmt.Errorf("%w: customer and idempotency key are required", ErrCommerceInvalidRecord) }
	idx := db.cipher.BlindIndex("sales-order:" + customerID + ":" + key)
	var id string
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesOrderIdempotency)
		if b == nil { return ErrCommerceRecordNotFound }
		v := b.Get([]byte(idx)); if v == nil { return ErrCommerceRecordNotFound }
		id = string(v); return nil
	})
	if err != nil { return nil, err }
	return db.GetSalesOrder(id)
}
func (db *DB) ListSalesOrdersByCustomer(customerID string, limit int) ([]SalesOrder, error) {
	return listCommercialIndexByPrefix[SalesOrder](db, bucketSalesOrderCustomer, bucketSalesOrders, strings.TrimSpace(customerID)+":", limit)
}

func listCommercialIndexByPrefix[T any](db *DB, indexName, recordsName []byte, prefix string, limit int) ([]T, error) {
	if db == nil || db.bolt == nil { return nil, errors.New("database is not open") }
	if limit <= 0 { limit = 50 }; if limit > 500 { limit = 500 }
	values := make([]T, 0, limit)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		index, records := tx.Bucket(indexName), tx.Bucket(recordsName)
		if index == nil { return nil }
		if records == nil { return errors.New("commercial index exists without its record bucket") }
		cursor := index.Cursor()
		for k, v := cursor.Seek([]byte(prefix)); k != nil && bytes.HasPrefix(k, []byte(prefix)); k, v = cursor.Next() {
			raw := records.Get(v); if raw == nil { return fmt.Errorf("commercial index points to missing record %q", v) }
			var item T
			if err := db.openCommercialRecord(raw, &item); err != nil { return err }
			values = append(values, item)
			if len(values) >= limit { break }
		}
		return nil
	})
	return values, err
}

func (db *DB) SaveSalesPayment(p SalesPayment) (SalesPayment, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return p, errors.New("sales payment storage requires an open database and master key") }
	if p.ID == "" { p.ID = GenerateUUID() }
	p.OrderID, p.CustomerID, p.Provider, p.ProviderReference = strings.TrimSpace(p.OrderID), strings.TrimSpace(p.CustomerID), strings.ToLower(strings.TrimSpace(p.Provider)), strings.TrimSpace(p.ProviderReference)
	var err error
	p.Currency, err = normaliseCommerceCurrency(p.Currency)
	if err != nil { return p, err }
	if p.OrderID == "" || p.CustomerID == "" || p.Provider == "" || p.AmountMinor < 0 { return p, fmt.Errorf("%w: payment order, customer, provider and non-negative amount are required", ErrCommerceInvalidRecord) }
	if p.Status == "" { p.Status = SalesPaymentPending }
	if !validPaymentStatus(p.Status) { return p, fmt.Errorf("%w: unknown payment status", ErrCommerceInvalidRecord) }
	now := time.Now().UTC(); if p.CreatedAt.IsZero() { p.CreatedAt = now }; p.UpdatedAt = now
	refKey := ""
	if p.ProviderReference != "" { refKey = db.cipher.BlindIndex("sales-payment:" + p.Provider + ":" + p.ProviderReference) }
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		payments, refs := tx.Bucket(bucketSalesPayments), tx.Bucket(bucketSalesPaymentReference)
		if payments == nil || refs == nil { return errors.New("sales payment buckets are missing") }
		var order SalesOrder
		found, err := readCommercialTx(db, tx, bucketSalesOrders, p.OrderID, &order)
		if err != nil { return err }
		if !found || order.CustomerID != p.CustomerID || order.AmountMinor != p.AmountMinor || order.Currency != p.Currency { return ErrCommerceForeignKey }
		var old SalesPayment
		oldRaw := payments.Get([]byte(p.ID)); exists := oldRaw != nil
		if exists {
			if err := db.openCommercialRecord(oldRaw, &old); err != nil { return err }
			if old.OrderID != p.OrderID || old.CustomerID != p.CustomerID || old.Provider != p.Provider || old.AmountMinor != p.AmountMinor || old.Currency != p.Currency {
				return fmt.Errorf("%w: payment order, customer, provider, amount and currency are immutable", ErrCommerceInvalidRecord)
			}
			if !canTransitionPayment(old.Status, p.Status) { return ErrCommerceTransition }
			p.CreatedAt = old.CreatedAt
			if old.ProviderReference != "" && old.ProviderReference != p.ProviderReference {
				oldRef := db.cipher.BlindIndex("sales-payment:" + old.Provider + ":" + old.ProviderReference)
				if err := refs.Delete([]byte(oldRef)); err != nil { return err }
			}
		}
		if refKey != "" { if owner := refs.Get([]byte(refKey)); owner != nil && string(owner) != p.ID { return ErrCommercePaymentRef } }
		raw, err := db.sealCommercialRecord(p); if err != nil { return err }
		if err := payments.Put([]byte(p.ID), raw); err != nil { return err }
		if refKey != "" { if err := refs.Put([]byte(refKey), []byte(p.ID)); err != nil { return err } }
		return nil
	})
	return p, err
}

func (db *DB) GetSalesPayment(id string) (*SalesPayment, error) {
	return getCommercialRecord[SalesPayment](db, bucketSalesPayments, id)
}
func (db *DB) GetSalesPaymentByProviderReference(provider, reference string) (*SalesPayment, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return nil, errors.New("sales payment storage requires an open database and master key") }
	provider, reference = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(reference)
	if provider == "" || reference == "" { return nil, fmt.Errorf("%w: provider and reference are required", ErrCommerceInvalidRecord) }
	idx := db.cipher.BlindIndex("sales-payment:" + provider + ":" + reference)
	var id string
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesPaymentReference); if b == nil { return ErrCommerceRecordNotFound }
		v := b.Get([]byte(idx)); if v == nil { return ErrCommerceRecordNotFound }; id = string(v); return nil
	})
	if err != nil { return nil, err }
	return db.GetSalesPayment(id)
}

func (db *DB) SaveCustomerSubscription(s CustomerSubscription) (CustomerSubscription, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return s, errors.New("subscription storage requires an open database and master key") }
	if s.ID == "" { s.ID = GenerateUUID() }
	s.CustomerID, s.PlanID, s.OrderID, s.ClientID = strings.TrimSpace(s.CustomerID), strings.TrimSpace(s.PlanID), strings.TrimSpace(s.OrderID), strings.TrimSpace(s.ClientID)
	if s.CustomerID == "" || s.PlanID == "" || s.OrderID == "" { return s, fmt.Errorf("%w: subscription customer, plan and order are required", ErrCommerceInvalidRecord) }
	if s.Status == "" { s.Status = CustomerSubscriptionPending }
	if !validCustomerSubscriptionStatus(s.Status) { return s, fmt.Errorf("%w: unknown subscription status", ErrCommerceInvalidRecord) }
	if s.Status == CustomerSubscriptionActive && s.ClientID == "" { return s, fmt.Errorf("%w: an active subscription must reference a DNS Client", ErrCommerceInvalidRecord) }
	if s.PlanSnapshot.ID != "" && s.PlanSnapshot.ID != s.PlanID { return s, fmt.Errorf("%w: plan snapshot does not match plan ID", ErrCommerceInvalidRecord) }
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() { s.CreatedAt = now }
	if s.Status == CustomerSubscriptionActive && s.StartedAt.IsZero() { s.StartedAt = now }
	if s.Status == CustomerSubscriptionActive && s.ExpiresAt.IsZero() && s.PlanSnapshot.DurationDays > 0 { s.ExpiresAt = s.StartedAt.AddDate(0, 0, s.PlanSnapshot.DurationDays) }
	s.UpdatedAt = now
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		subs, index := tx.Bucket(bucketSalesSubscriptions), tx.Bucket(bucketSalesSubscriptionCustomer)
		if subs == nil || index == nil { return errors.New("subscription buckets are missing") }
		var customer CommerceCustomer
		found, err := readCommercialTx(db, tx, bucketSalesCustomers, s.CustomerID, &customer)
		if err != nil { return err }; if !found { return ErrCommerceForeignKey }
		var plan SalesPlan
		found, err = readCommercialTx(db, tx, bucketSalesPlans, s.PlanID, &plan)
		if err != nil { return err }; if !found { return ErrCommerceForeignKey }
		var order SalesOrder
		found, err = readCommercialTx(db, tx, bucketSalesOrders, s.OrderID, &order)
		if err != nil { return err }
		if !found || order.CustomerID != s.CustomerID || order.PlanID != s.PlanID || order.Status != SalesOrderPaid || order.PlanSnapshot.ID != s.PlanID { return ErrCommerceForeignKey }
		// The paid order is authoritative for the benefits purchased by this customer.
		s.PlanSnapshot = order.PlanSnapshot
		if err := validateSalesPlan(&s.PlanSnapshot); err != nil { return err }
		if s.ClientID != "" && (tx.Bucket(bucketClients) == nil || tx.Bucket(bucketClients).Get([]byte(s.ClientID)) == nil) {
			return fmt.Errorf("%w: DNS Client %q does not exist", ErrCommerceForeignKey, s.ClientID)
		}
		var old CustomerSubscription
		oldRaw := subs.Get([]byte(s.ID)); exists := oldRaw != nil
		if exists {
			if err := db.openCommercialRecord(oldRaw, &old); err != nil { return err }
			if old.CustomerID != s.CustomerID || old.PlanID != s.PlanID || old.OrderID != s.OrderID || old.PlanSnapshot.ID != s.PlanSnapshot.ID {
				return fmt.Errorf("%w: subscription ownership and plan snapshot are immutable", ErrCommerceInvalidRecord)
			}
			if old.ClientID != "" && old.ClientID != s.ClientID { return fmt.Errorf("%w: DNS Client binding is immutable once set", ErrCommerceInvalidRecord) }
			if !canTransitionCustomerSubscription(old.Status, s.Status) { return ErrCommerceTransition }
			s.CreatedAt = old.CreatedAt
			if !old.StartedAt.IsZero() { s.StartedAt = old.StartedAt }
			if !old.ExpiresAt.IsZero() && s.ExpiresAt.IsZero() { s.ExpiresAt = old.ExpiresAt }
		}
		raw, err := db.sealCommercialRecord(s); if err != nil { return err }
		if err := subs.Put([]byte(s.ID), raw); err != nil { return err }
		return index.Put([]byte(s.CustomerID+":"+s.ID), []byte(s.ID))
	})
	return s, err
}

func (db *DB) GetCustomerSubscription(id string) (*CustomerSubscription, error) {
	return getCommercialRecord[CustomerSubscription](db, bucketSalesSubscriptions, id)
}
func (db *DB) ListCustomerSubscriptions(customerID string, limit int) ([]CustomerSubscription, error) {
	return listCommercialIndexByPrefix[CustomerSubscription](db, bucketSalesSubscriptionCustomer, bucketSalesSubscriptions, strings.TrimSpace(customerID)+":", limit)
}

func (db *DB) AppendCommercialAuditEvent(event CommercialAuditEvent) (CommercialAuditEvent, error) {
	if db == nil || db.bolt == nil || db.cipher == nil { return event, errors.New("commercial audit storage requires an open database and master key") }
	event.ActorType, event.ActorID = strings.TrimSpace(event.ActorType), strings.TrimSpace(event.ActorID)
	event.Action, event.EntityType = strings.TrimSpace(event.Action), strings.TrimSpace(event.EntityType)
	event.EntityID, event.Summary = strings.TrimSpace(event.EntityID), strings.TrimSpace(event.Summary)
	if event.Action == "" || event.EntityType == "" { return event, fmt.Errorf("%w: audit action and entity type are required", ErrCommerceInvalidRecord) }
	if event.ID == "" { event.ID = GenerateUUID() }
	if event.CreatedAt.IsZero() { event.CreatedAt = time.Now().UTC() }
	if event.Metadata == nil { event.Metadata = map[string]string{} }
	raw, err := db.sealCommercialRecord(event); if err != nil { return event, err }
	key := fmt.Sprintf("%020d:%s", event.CreatedAt.UTC().UnixNano(), event.ID)
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesAuditEvents); if b == nil { return errors.New("commercial audit bucket is missing") }
		if b.Get([]byte(key)) != nil { return ErrCommerceRecordExists }
		return b.Put([]byte(key), raw)
	})
	return event, err
}

func (db *DB) ListCommercialAuditEvents(limit int) ([]CommercialAuditEvent, error) {
	if db == nil || db.bolt == nil { return nil, errors.New("database is not open") }
	if limit <= 0 { limit = 100 }; if limit > 500 { limit = 500 }
	events := make([]CommercialAuditEvent, 0, limit)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSalesAuditEvents); if b == nil { return nil }
		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil && len(events) < limit; k, v = cursor.Prev() {
			var event CommercialAuditEvent
			if err := db.openCommercialRecord(v, &event); err != nil { return err }
			events = append(events, event)
		}
		return nil
	})
	return events, err
}

// ValidateCommercialState is read-only and tolerates absent buckets from older
// releases. Once a commercial record exists, it verifies encryption and the
// indexes/references required to avoid turning a corrupt store into empty sales
// history during startup.
func (db *DB) ValidateCommercialState() error {
	if db == nil || db.bolt == nil { return errors.New("database is not open") }
	return db.bolt.View(func(tx *bolt.Tx) error {
		customers := tx.Bucket(bucketSalesCustomers)
		if customers != nil {
			if err := customers.ForEach(func(k, raw []byte) error {
				var c CommerceCustomer
				if err := db.openCommercialRecord(raw, &c); err != nil { return fmt.Errorf("validate sales customer %q: %w", k, err) }
				email, err := normaliseCommerceEmail(c.Email)
				if err != nil || email != c.Email || c.ID != string(k) || c.PasswordHash == "" { return fmt.Errorf("validate sales customer %q: invalid identity record", k) }
				idx := tx.Bucket(bucketSalesCustomerEmail)
				if idx == nil || string(idx.Get([]byte(db.cipher.BlindIndex("sales-email:"+c.Email)))) != c.ID { return fmt.Errorf("validate sales customer %q: email index mismatch", k) }
				if c.TelegramUserID > 0 {
					tg := tx.Bucket(bucketSalesCustomerTelegram)
					if tg == nil || string(tg.Get([]byte(strconv.FormatInt(c.TelegramUserID, 10)))) != c.ID { return fmt.Errorf("validate sales customer %q: Telegram index mismatch", k) }
				}
				return nil
			}); err != nil { return err }
		}
		plans := tx.Bucket(bucketSalesPlans)
		if plans != nil {
			if err := plans.ForEach(func(k, raw []byte) error {
				var p SalesPlan
				if err := db.openCommercialRecord(raw, &p); err != nil { return fmt.Errorf("validate sales plan %q: %w", k, err) }
				if p.ID != string(k) { return fmt.Errorf("validate sales plan %q: ID mismatch", k) }
				return validateSalesPlan(&p)
			}); err != nil { return err }
		}
		orders := tx.Bucket(bucketSalesOrders)
		if orders != nil {
			if err := orders.ForEach(func(k, raw []byte) error {
				var o SalesOrder
				if err := db.openCommercialRecord(raw, &o); err != nil { return fmt.Errorf("validate sales order %q: %w", k, err) }
				if o.ID != string(k) || o.CustomerID == "" || o.PlanID == "" || o.PlanName == "" || o.AmountMinor < 0 || !validOrderStatus(o.Status) ||
					o.PlanSnapshot.ID != o.PlanID || o.PlanSnapshot.Name != o.PlanName || o.PlanSnapshot.PriceMinor != o.AmountMinor || o.PlanSnapshot.Currency != o.Currency {
					return fmt.Errorf("validate sales order %q: invalid record or plan snapshot", k)
				}
				snapshot := o.PlanSnapshot
				if err := validateSalesPlan(&snapshot); err != nil { return fmt.Errorf("validate sales order %q: invalid plan snapshot: %w", k, err) }
				var c CommerceCustomer
				found, err := readCommercialTx(db, tx, bucketSalesCustomers, o.CustomerID, &c)
				if err != nil || !found { return fmt.Errorf("validate sales order %q: customer reference is invalid", k) }
				var p SalesPlan
				found, err = readCommercialTx(db, tx, bucketSalesPlans, o.PlanID, &p)
				if err != nil || !found { return fmt.Errorf("validate sales order %q: plan reference is invalid", k) }
				if o.IdempotencyKey != "" {
					idx := tx.Bucket(bucketSalesOrderIdempotency)
					expected := db.cipher.BlindIndex("sales-order:"+o.CustomerID+":"+o.IdempotencyKey)
					if idx == nil || string(idx.Get([]byte(expected))) != o.ID { return fmt.Errorf("validate sales order %q: idempotency index mismatch", k) }
				}
				idx := tx.Bucket(bucketSalesOrderCustomer)
				if idx == nil || string(idx.Get([]byte(o.CustomerID+":"+o.ID))) != o.ID { return fmt.Errorf("validate sales order %q: customer index mismatch", k) }
				return nil
			}); err != nil { return err }
		}
		payments := tx.Bucket(bucketSalesPayments)
		if payments != nil {
			if err := payments.ForEach(func(k, raw []byte) error {
				var p SalesPayment
				if err := db.openCommercialRecord(raw, &p); err != nil { return fmt.Errorf("validate sales payment %q: %w", k, err) }
				if p.ID != string(k) || p.AmountMinor < 0 || p.Provider == "" || !validPaymentStatus(p.Status) { return fmt.Errorf("validate sales payment %q: invalid record", k) }
				var o SalesOrder
				found, err := readCommercialTx(db, tx, bucketSalesOrders, p.OrderID, &o)
				if err != nil || !found || o.CustomerID != p.CustomerID || o.AmountMinor != p.AmountMinor || o.Currency != p.Currency { return fmt.Errorf("validate sales payment %q: order reference is invalid", k) }
				if p.ProviderReference != "" {
					idx := tx.Bucket(bucketSalesPaymentReference)
					expected := db.cipher.BlindIndex("sales-payment:"+p.Provider+":"+p.ProviderReference)
					if idx == nil || string(idx.Get([]byte(expected))) != p.ID { return fmt.Errorf("validate sales payment %q: provider reference index mismatch", k) }
				}
				return nil
			}); err != nil { return err }
		}
		subs := tx.Bucket(bucketSalesSubscriptions)
		if subs != nil {
			if err := subs.ForEach(func(k, raw []byte) error {
				var s CustomerSubscription
				if err := db.openCommercialRecord(raw, &s); err != nil { return fmt.Errorf("validate subscription %q: %w", k, err) }
				if s.ID != string(k) || !validCustomerSubscriptionStatus(s.Status) || s.PlanSnapshot.ID != s.PlanID { return fmt.Errorf("validate subscription %q: invalid record", k) }
				var c CommerceCustomer
				found, err := readCommercialTx(db, tx, bucketSalesCustomers, s.CustomerID, &c)
				if err != nil || !found { return fmt.Errorf("validate subscription %q: customer reference is invalid", k) }
				var o SalesOrder
				found, err = readCommercialTx(db, tx, bucketSalesOrders, s.OrderID, &o)
				if err != nil || !found || o.CustomerID != s.CustomerID || o.PlanID != s.PlanID || (s.Status != CustomerSubscriptionCancelled && o.Status != SalesOrderPaid) { return fmt.Errorf("validate subscription %q: order reference is invalid", k) }
				idx := tx.Bucket(bucketSalesSubscriptionCustomer)
				if idx == nil || string(idx.Get([]byte(s.CustomerID+":"+s.ID))) != s.ID { return fmt.Errorf("validate subscription %q: customer index mismatch", k) }
				if s.ClientID != "" && (tx.Bucket(bucketClients) == nil || tx.Bucket(bucketClients).Get([]byte(s.ClientID)) == nil) { return fmt.Errorf("validate subscription %q: DNS Client reference is invalid", k) }
				return nil
			}); err != nil { return err }
		}
		audit := tx.Bucket(bucketSalesAuditEvents)
		if audit != nil {
			if err := audit.ForEach(func(_, raw []byte) error {
				var event CommercialAuditEvent
				if err := db.openCommercialRecord(raw, &event); err != nil { return fmt.Errorf("validate commercial audit event: %w", err) }
				if event.ID == "" || event.Action == "" || event.EntityType == "" { return errors.New("validate commercial audit event: required fields missing") }
				return nil
			}); err != nil { return err }
		}
		return nil
	})
}
