package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketCommerceRoot          = []byte("commerce")
	bucketCommerceCustomers     = []byte("customers")
	bucketCommerceCustomerEmail = []byte("customer_email_index")
	bucketCommercePlans         = []byte("plans")
	bucketCommerceOrders        = []byte("orders")
	bucketCommercePayments      = []byte("payments")
	bucketCommerceEvents        = []byte("payment_events")
	bucketCommerceProviderRefs  = []byte("provider_payment_refs")
)

// CommerceRepository stores sales records in additional bbolt buckets inside
// the existing HyperDNS database. Constructing it is additive: it neither
// rewrites nor migrates existing DNS Client records.
type CommerceRepository struct {
	db *DB
}

func NewCommerceRepository(db *DB) (*CommerceRepository, error) {
	if db == nil || db.bolt == nil {
		return nil, errors.New("commerce repository requires an open HyperDNS database")
	}
	if db.cipher == nil {
		return nil, errors.New("commerce repository requires the loaded master-key cipher")
	}
	r := &CommerceRepository{db: db}
	if err := r.ensureSchema(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CommerceRepository) ensureSchema() error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(bucketCommerceRoot)
		if err != nil {
			return fmt.Errorf("create commerce bucket: %w", err)
		}
		for _, name := range [][]byte{
			bucketCommerceCustomers,
			bucketCommerceCustomerEmail,
			bucketCommercePlans,
			bucketCommerceOrders,
			bucketCommercePayments,
			bucketCommerceEvents,
			bucketCommerceProviderRefs,
		} {
			if _, err := root.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create commerce sub-bucket %q: %w", name, err)
			}
		}
		return nil
	})
}

func (r *CommerceRepository) table(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
	if r == nil || r.db == nil || r.db.bolt == nil {
		return nil, errors.New("commerce repository is not initialized")
	}
	root := tx.Bucket(bucketCommerceRoot)
	if root == nil {
		return nil, ErrCommerceSchemaMissing
	}
	table := root.Bucket(name)
	if table == nil {
		return nil, fmt.Errorf("%w: missing %q bucket", ErrCommerceSchemaMissing, name)
	}
	return table, nil
}

// CreateCustomer stores an encrypted email and display name plus a one-way
// password hash. passwordHash must be produced by the authentication layer;
// plaintext passwords must never be passed here.
func (r *CommerceRepository) CreateCustomer(customer CommerceCustomer, passwordHash string) (CommerceCustomer, error) {
	email, err := normalizeCommerceEmail(customer.Email)
	if err != nil {
		return CommerceCustomer{}, err
	}
	if strings.TrimSpace(passwordHash) == "" {
		return CommerceCustomer{}, fmt.Errorf("%w: password hash is required", ErrCommerceInvalidRecord)
	}
	customer.ID = strings.TrimSpace(customer.ID)
	if customer.ID == "" {
		customer.ID = uuid.NewString()
	}
	if len(customer.ID) > 128 {
		return CommerceCustomer{}, fmt.Errorf("%w: customer ID is too long", ErrCommerceInvalidRecord)
	}
	customer.Email = email
	customer.DisplayName = strings.TrimSpace(customer.DisplayName)
	if len(customer.DisplayName) > 120 {
		return CommerceCustomer{}, fmt.Errorf("%w: display name is too long", ErrCommerceInvalidRecord)
	}
	if customer.Status == "" {
		customer.Status = CommerceCustomerActive
	}
	if err := validateCommerceCustomerStatus(customer.Status); err != nil {
		return CommerceCustomer{}, err
	}
	now := time.Now().UTC()
	if customer.CreatedAt.IsZero() {
		customer.CreatedAt = now
	}
	customer.UpdatedAt = now

	emailIndex := r.db.cipher.BlindIndex(email)
	if emailIndex == "" {
		return CommerceCustomer{}, errors.New("could not derive customer email index")
	}
	emailEnc, err := r.db.cipher.EncryptString(email)
	if err != nil {
		return CommerceCustomer{}, fmt.Errorf("encrypt customer email: %w", err)
	}
	nameEnc, err := r.db.cipher.EncryptString(customer.DisplayName)
	if err != nil {
		return CommerceCustomer{}, fmt.Errorf("encrypt customer display name: %w", err)
	}
	stored := storedCommerceCustomer{
		ID:             customer.ID,
		EmailEnc:       emailEnc,
		EmailIndex:     emailIndex,
		DisplayNameEnc: nameEnc,
		PasswordHash:   passwordHash,
		Status:         customer.Status,
		CreatedAt:      customer.CreatedAt,
		UpdatedAt:      customer.UpdatedAt,
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return CommerceCustomer{}, err
	}

	err = r.db.bolt.Update(func(tx *bolt.Tx) error {
		customers, err := r.table(tx, bucketCommerceCustomers)
		if err != nil {
			return err
		}
		emailTable, err := r.table(tx, bucketCommerceCustomerEmail)
		if err != nil {
			return err
		}
		if emailTable.Get([]byte(emailIndex)) != nil {
			return ErrCommerceEmailExists
		}
		if customers.Get([]byte(customer.ID)) != nil {
			return fmt.Errorf("%w: customer ID already exists", ErrCommerceInvalidRecord)
		}
		if err := customers.Put([]byte(customer.ID), data); err != nil {
			return err
		}
		return emailTable.Put([]byte(emailIndex), []byte(customer.ID))
	})
	if err != nil {
		return CommerceCustomer{}, err
	}
	return customer, nil
}

func (r *CommerceRepository) loadCustomerTx(tx *bolt.Tx, id string) (CommerceCustomer, string, error) {
	customers, err := r.table(tx, bucketCommerceCustomers)
	if err != nil {
		return CommerceCustomer{}, "", err
	}
	raw := customers.Get([]byte(id))
	if raw == nil {
		return CommerceCustomer{}, "", ErrCommerceNotFound
	}
	var stored storedCommerceCustomer
	if err := json.Unmarshal(raw, &stored); err != nil {
		return CommerceCustomer{}, "", fmt.Errorf("decode customer %q: %w", id, err)
	}
	email, err := r.db.cipher.DecryptString(stored.EmailEnc)
	if err != nil {
		return CommerceCustomer{}, "", fmt.Errorf("decrypt customer email %q: %w", id, err)
	}
	name, err := r.db.cipher.DecryptString(stored.DisplayNameEnc)
	if err != nil {
		return CommerceCustomer{}, "", fmt.Errorf("decrypt customer display name %q: %w", id, err)
	}
	normalized, err := normalizeCommerceEmail(email)
	if err != nil || r.db.cipher.BlindIndex(normalized) != stored.EmailIndex {
		return CommerceCustomer{}, "", fmt.Errorf("%w: customer email index does not match stored email", ErrCommerceInvalidRecord)
	}
	return CommerceCustomer{
		ID:          stored.ID,
		Email:       email,
		DisplayName: name,
		Status:      stored.Status,
		CreatedAt:   stored.CreatedAt,
		UpdatedAt:   stored.UpdatedAt,
	}, stored.PasswordHash, nil
}

func (r *CommerceRepository) GetCustomer(id string) (CommerceCustomer, error) {
	var out CommerceCustomer
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		customer, _, err := r.loadCustomerTx(tx, id)
		out = customer
		return err
	})
	return out, err
}

// GetCustomerForAuthentication is intended only for the login service. Never
// serialize or log the returned password hash.
func (r *CommerceRepository) GetCustomerForAuthentication(email string) (CommerceCustomer, string, error) {
	email, err := normalizeCommerceEmail(email)
	if err != nil {
		return CommerceCustomer{}, "", err
	}
	index := r.db.cipher.BlindIndex(email)
	var customer CommerceCustomer
	var passwordHash string
	err = r.db.bolt.View(func(tx *bolt.Tx) error {
		emailTable, err := r.table(tx, bucketCommerceCustomerEmail)
		if err != nil {
			return err
		}
		id := emailTable.Get([]byte(index))
		if id == nil {
			return ErrCommerceNotFound
		}
		customer, passwordHash, err = r.loadCustomerTx(tx, string(id))
		return err
	})
	return customer, passwordHash, err
}

func (r *CommerceRepository) SetCustomerStatus(id string, status CommerceCustomerStatus) error {
	if err := validateCommerceCustomerStatus(status); err != nil {
		return err
	}
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		customers, err := r.table(tx, bucketCommerceCustomers)
		if err != nil {
			return err
		}
		raw := customers.Get([]byte(id))
		if raw == nil {
			return ErrCommerceNotFound
		}
		var stored storedCommerceCustomer
		if err := json.Unmarshal(raw, &stored); err != nil {
			return fmt.Errorf("decode customer %q: %w", id, err)
		}
		stored.Status = status
		stored.UpdatedAt = time.Now().UTC()
		data, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		return customers.Put([]byte(id), data)
	})
}

func (r *CommerceRepository) SavePlan(plan CommercePlan) (CommercePlan, error) {
	plan, err := normalizeAndValidateCommercePlan(plan)
	if err != nil {
		return CommercePlan{}, err
	}
	if plan.ID == "" {
		return CommercePlan{}, fmt.Errorf("%w: plan ID is required", ErrCommerceInvalidRecord)
	}
	now := time.Now().UTC()
	plan.UpdatedAt = now
	err = r.db.bolt.Update(func(tx *bolt.Tx) error {
		plans, err := r.table(tx, bucketCommercePlans)
		if err != nil {
			return err
		}
		if raw := plans.Get([]byte(plan.ID)); raw != nil {
			var old CommercePlan
			if err := json.Unmarshal(raw, &old); err != nil {
				return fmt.Errorf("decode existing plan %q: %w", plan.ID, err)
			}
			plan.CreatedAt = old.CreatedAt
		} else if plan.CreatedAt.IsZero() {
			plan.CreatedAt = now
		}
		data, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		return plans.Put([]byte(plan.ID), data)
	})
	if err != nil {
		return CommercePlan{}, err
	}
	return plan, nil
}

func (r *CommerceRepository) GetPlan(id string) (CommercePlan, error) {
	var out CommercePlan
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		plans, err := r.table(tx, bucketCommercePlans)
		if err != nil {
			return err
		}
		raw := plans.Get([]byte(id))
		if raw == nil {
			return ErrCommerceNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

func (r *CommerceRepository) ListPlans(enabledOnly bool) ([]CommercePlan, error) {
	out := []CommercePlan{}
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		plans, err := r.table(tx, bucketCommercePlans)
		if err != nil {
			return err
		}
		return plans.ForEach(func(_, raw []byte) error {
			var plan CommercePlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				return err
			}
			if !enabledOnly || plan.Enabled {
				out = append(out, plan)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Name < out[j].Name
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, err
}

// CreateOrder creates an immutable snapshot from an active customer and an
// enabled plan. No DNS Client is created until a verified payment is fulfilled.
func (r *CommerceRepository) CreateOrder(customerID, planID string) (CommerceOrder, error) {
	var out CommerceOrder
	err := r.db.bolt.Update(func(tx *bolt.Tx) error {
		customer, _, err := r.loadCustomerTx(tx, customerID)
		if err != nil {
			return err
		}
		if customer.Status != CommerceCustomerActive {
			return ErrCommerceCustomerSuspended
		}
		plans, err := r.table(tx, bucketCommercePlans)
		if err != nil {
			return err
		}
		rawPlan := plans.Get([]byte(planID))
		if rawPlan == nil {
			return ErrCommerceNotFound
		}
		var plan CommercePlan
		if err := json.Unmarshal(rawPlan, &plan); err != nil {
			return fmt.Errorf("decode plan %q: %w", planID, err)
		}
		if !plan.Enabled {
			return ErrCommercePlanDisabled
		}
		now := time.Now().UTC()
		out = CommerceOrder{
			ID:                uuid.NewString(),
			CustomerID:        customer.ID,
			PlanID:            plan.ID,
			PlanName:          plan.Name,
			Currency:          plan.Currency,
			AmountMinor:       plan.PriceMinor,
			DurationDays:      plan.DurationDays,
			Lifetime:          plan.Lifetime,
			TrafficLimitGB:    plan.TrafficLimitGB,
			TrafficResetCycle: plan.TrafficResetCycle,
			Policies:          append([]string{}, plan.Policies...),
			Status:            CommerceOrderPending,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		data, err := json.Marshal(out)
		if err != nil {
			return err
		}
		orders, err := r.table(tx, bucketCommerceOrders)
		if err != nil {
			return err
		}
		return orders.Put([]byte(out.ID), data)
	})
	return out, err
}

func (r *CommerceRepository) loadOrderTx(tx *bolt.Tx, id string) (CommerceOrder, error) {
	orders, err := r.table(tx, bucketCommerceOrders)
	if err != nil {
		return CommerceOrder{}, err
	}
	raw := orders.Get([]byte(id))
	if raw == nil {
		return CommerceOrder{}, ErrCommerceNotFound
	}
	var order CommerceOrder
	if err := json.Unmarshal(raw, &order); err != nil {
		return CommerceOrder{}, fmt.Errorf("decode order %q: %w", id, err)
	}
	return order, nil
}

func (r *CommerceRepository) GetOrder(id string) (CommerceOrder, error) {
	var out CommerceOrder
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		order, err := r.loadOrderTx(tx, id)
		out = order
		return err
	})
	return out, err
}

func (r *CommerceRepository) ListCustomerOrders(customerID string, limit int) ([]CommerceOrder, error) {
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("%w: order limit must be between 1 and 500", ErrCommerceInvalidRecord)
	}
	out := []CommerceOrder{}
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		if _, _, err := r.loadCustomerTx(tx, customerID); err != nil {
			return err
		}
		orders, err := r.table(tx, bucketCommerceOrders)
		if err != nil {
			return err
		}
		return orders.ForEach(func(_, raw []byte) error {
			var order CommerceOrder
			if err := json.Unmarshal(raw, &order); err != nil {
				return err
			}
			if order.CustomerID == customerID {
				out = append(out, order)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, err
}

func (r *CommerceRepository) CancelOrder(orderID, customerID string) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		order, err := r.loadOrderTx(tx, orderID)
		if err != nil {
			return err
		}
		if order.CustomerID != customerID {
			return ErrCommerceNotFound
		}
		if order.Status != CommerceOrderPending {
			return ErrCommerceOrderNotPending
		}
		order.Status = CommerceOrderCancelled
		order.UpdatedAt = time.Now().UTC()
		data, err := json.Marshal(order)
		if err != nil {
			return err
		}
		orders, err := r.table(tx, bucketCommerceOrders)
		if err != nil {
			return err
		}
		return orders.Put([]byte(order.ID), data)
	})
}

// ConfirmOrderPayment must only be called after the provider adapter has
// verified the webhook signature or performed a server-to-server confirmation.
// The order status, payment record and webhook idempotency marker are committed
// in one bbolt transaction. A duplicate event/reference returns replay=true.
func (r *CommerceRepository) ConfirmOrderPayment(
	provider, eventID, providerPaymentID, orderID string,
	amountMinor int64, currency string,
) (CommerceOrder, bool, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	eventID = strings.TrimSpace(eventID)
	providerPaymentID = strings.TrimSpace(providerPaymentID)
	orderID = strings.TrimSpace(orderID)
	currency = strings.TrimSpace(currency)
	if len(provider) < 2 || len(provider) > 32 || eventID == "" || providerPaymentID == "" || orderID == "" ||
		amountMinor <= 0 || !commerceCurrencyPattern.MatchString(currency) {
		return CommerceOrder{}, false, fmt.Errorf("%w: invalid verified payment fields", ErrCommerceInvalidRecord)
	}
	eventKey := r.db.cipher.BlindIndex(provider + "\x00event\x00" + eventID)
	refKey := r.db.cipher.BlindIndex(provider + "\x00payment\x00" + providerPaymentID)
	if eventKey == "" || refKey == "" {
		return CommerceOrder{}, false, errors.New("could not derive payment idempotency index")
	}

	var out CommerceOrder
	replay := false
	err := r.db.bolt.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(bucketCommerceRoot)
		if root == nil {
			return ErrCommerceSchemaMissing
		}
		events := root.Bucket(bucketCommerceEvents)
		payments := root.Bucket(bucketCommercePayments)
		refs := root.Bucket(bucketCommerceProviderRefs)
		if events == nil || payments == nil || refs == nil {
			return ErrCommerceSchemaMissing
		}
		if raw := events.Get([]byte(eventKey)); raw != nil {
			var previous commercePaymentEvent
			if err := json.Unmarshal(raw, &previous); err != nil {
				return fmt.Errorf("decode payment event: %w", err)
			}
			if previous.OrderID != orderID || previous.ProviderPaymentID != providerPaymentID ||
				previous.AmountMinor != amountMinor || previous.Currency != currency {
				return ErrCommercePaymentDuplicate
			}
			order, err := r.loadOrderTx(tx, previous.OrderID)
			if err != nil {
				return err
			}
			out, replay = order, true
			return nil
		}

		if paymentID := refs.Get([]byte(refKey)); paymentID != nil {
			rawPayment := payments.Get(paymentID)
			if rawPayment == nil {
				return fmt.Errorf("%w: provider payment index points to a missing payment", ErrCommerceInvalidRecord)
			}
			var previous CommercePayment
			if err := json.Unmarshal(rawPayment, &previous); err != nil {
				return err
			}
			if previous.OrderID != orderID || previous.AmountMinor != amountMinor || previous.Currency != currency {
				return ErrCommercePaymentDuplicate
			}
			order, err := r.loadOrderTx(tx, orderID)
			if err != nil {
				return err
			}
			event := commercePaymentEvent{
				OrderID:           orderID,
				PaymentID:         previous.ID,
				ProviderPaymentID: providerPaymentID,
				AmountMinor:       amountMinor,
				Currency:          currency,
				CreatedAt:         time.Now().UTC(),
			}
			encodedEvent, err := json.Marshal(event)
			if err != nil {
				return err
			}
			if err := events.Put([]byte(eventKey), encodedEvent); err != nil {
				return err
			}
			out, replay = order, true
			return nil
		}

		order, err := r.loadOrderTx(tx, orderID)
		if err != nil {
			return err
		}
		if order.Status == CommerceOrderPaid || order.Status == CommerceOrderFulfilled {
			return ErrCommerceOrderAlreadyPaid
		}
		if order.Status != CommerceOrderPending {
			return ErrCommerceOrderNotPending
		}
		if order.AmountMinor != amountMinor || order.Currency != currency {
			return fmt.Errorf("%w: verified amount or currency does not match order snapshot", ErrCommerceInvalidRecord)
		}

		now := time.Now().UTC()
		payment := CommercePayment{
			ID:                uuid.NewString(),
			OrderID:           orderID,
			Provider:          provider,
			ProviderPaymentID: providerPaymentID,
			AmountMinor:       amountMinor,
			Currency:          currency,
			Status:            CommercePaymentConfirmed,
			CreatedAt:         now,
			ConfirmedAt:       now,
		}
		paymentData, err := json.Marshal(payment)
		if err != nil {
			return err
		}
		event := commercePaymentEvent{
			OrderID:           orderID,
			PaymentID:         payment.ID,
			ProviderPaymentID: providerPaymentID,
			AmountMinor:       amountMinor,
			Currency:          currency,
			CreatedAt:         now,
		}
		eventData, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err := payments.Put([]byte(payment.ID), paymentData); err != nil {
			return err
		}
		if err := refs.Put([]byte(refKey), []byte(payment.ID)); err != nil {
			return err
		}
		if err := events.Put([]byte(eventKey), eventData); err != nil {
			return err
		}
		order.Status = CommerceOrderPaid
		order.PaidAt = now
		order.UpdatedAt = now
		orderData, err := json.Marshal(order)
		if err != nil {
			return err
		}
		orders, err := r.table(tx, bucketCommerceOrders)
		if err != nil {
			return err
		}
		if err := orders.Put([]byte(order.ID), orderData); err != nil {
			return err
		}
		out = order
		return nil
	})
	return out, replay, err
}

// MarkOrderFulfilled attaches the provisioned HyperDNS Client to an already-paid
// order. It is idempotent for the same Client ID, which lets a retry recover from
// a crash between payment confirmation and a successful HTTP response.
func (r *CommerceRepository) MarkOrderFulfilled(orderID, clientID string) (CommerceOrder, error) {
	orderID = strings.TrimSpace(orderID)
	clientID = strings.TrimSpace(clientID)
	if orderID == "" || clientID == "" {
		return CommerceOrder{}, fmt.Errorf("%w: order and client IDs are required", ErrCommerceInvalidRecord)
	}
	var out CommerceOrder
	err := r.db.bolt.Update(func(tx *bolt.Tx) error {
		order, err := r.loadOrderTx(tx, orderID)
		if err != nil {
			return err
		}
		if order.Status == CommerceOrderFulfilled {
			if order.ClientID != clientID {
				return fmt.Errorf("%w: order is already fulfilled by a different client", ErrCommerceInvalidRecord)
			}
			out = order
			return nil
		}
		if order.Status != CommerceOrderPaid {
			return ErrCommerceOrderNotPending
		}
		now := time.Now().UTC()
		order.Status = CommerceOrderFulfilled
		order.ClientID = clientID
		order.FulfilledAt = now
		order.UpdatedAt = now
		data, err := json.Marshal(order)
		if err != nil {
			return err
		}
		orders, err := r.table(tx, bucketCommerceOrders)
		if err != nil {
			return err
		}
		if err := orders.Put([]byte(order.ID), data); err != nil {
			return err
		}
		out = order
		return nil
	})
	return out, err
}

func (r *CommerceRepository) ListPayments(orderID string) ([]CommercePayment, error) {
	out := []CommercePayment{}
	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		if _, err := r.loadOrderTx(tx, orderID); err != nil {
			return err
		}
		payments, err := r.table(tx, bucketCommercePayments)
		if err != nil {
			return err
		}
		return payments.ForEach(func(_, raw []byte) error {
			var payment CommercePayment
			if err := json.Unmarshal(raw, &payment); err != nil {
				return err
			}
			if payment.OrderID == orderID {
				out = append(out, payment)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}
