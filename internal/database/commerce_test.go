package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hyperdns/internal/crypto"
)

func openCommerceFixture(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "commerce.db")
	key := make([]byte, 32)
	for i := range key { key[i] = byte(i + 31) }
	cipher, err := crypto.NewCipher(key)
	if err != nil { t.Fatalf("create cipher: %v", err) }
	db, err := Open(path, cipher)
	if err != nil { t.Fatalf("open database: %v", err) }
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func createCommerceFixtures(t *testing.T, db *DB) (CommerceCustomer, SalesPlan) {
	t.Helper()
	customer, err := db.CreateCommerceCustomer(CommerceCustomer{
		Email: "gamer@example.com", DisplayName: "Test Gamer", PasswordHash: "test-hash-not-a-password",
	})
	if err != nil { t.Fatalf("create customer: %v", err) }
	plan, err := db.CreateSalesPlan(SalesPlan{
		Name: "Monthly Gamer", Description: "Test plan", PriceMinor: 499, Currency: "USD",
		DurationDays: 30, TrafficLimitGB: 50, TrafficResetCycle: "monthly",
		PolicyIDs: []string{"enable_riot", "enable_steam"}, Active: true,
	})
	if err != nil { t.Fatalf("create plan: %v", err) }
	return customer, plan
}

func TestCommerceCustomerEmailIndexAndEncryption(t *testing.T) {
	db, path := openCommerceFixture(t)
	customer, err := db.CreateCommerceCustomer(CommerceCustomer{
		Email: "Gamer@Example.com", DisplayName: "Gamer One", PasswordHash: "test-password-verifier",
		TelegramUserID: 123456789,
	})
	if err != nil { t.Fatalf("create customer: %v", err) }
	if customer.Email != "gamer@example.com" { t.Fatalf("email not normalised: %q", customer.Email) }
	found, err := db.GetCommerceCustomerByEmail("  GAMER@example.com ")
	if err != nil || found.ID != customer.ID { t.Fatalf("email lookup failed: customer=%+v err=%v", found, err) }
	byTelegram, err := db.GetCommerceCustomerByTelegramID(123456789)
	if err != nil || byTelegram.ID != customer.ID { t.Fatalf("Telegram lookup failed: customer=%+v err=%v", byTelegram, err) }
	if _, err := db.CreateCommerceCustomer(CommerceCustomer{
		Email: "gamer@example.com", DisplayName: "Duplicate", PasswordHash: "another-hash",
	}); !errors.Is(err, ErrCommerceEmailTaken) { t.Fatalf("duplicate email accepted: %v", err) }
	raw, err := os.ReadFile(path)
	if err != nil { t.Fatalf("read database: %v", err) }
	if bytes.Contains(raw, []byte("gamer@example.com")) || bytes.Contains(raw, []byte("test-password-verifier")) {
		t.Fatal("customer email or password verifier was stored in cleartext")
	}
	if err := db.ValidateCommercialState(); err != nil { t.Fatalf("validate commercial state: %v", err) }
}

func TestCommerceOrderPaymentAndSubscriptionLifecycle(t *testing.T) {
	db, _ := openCommerceFixture(t)
	customer, plan := createCommerceFixtures(t, db)
	order, err := db.SaveSalesOrder(SalesOrder{
		CustomerID: customer.ID, PlanID: plan.ID, PlanName: plan.Name, AmountMinor: plan.PriceMinor,
		Currency: plan.Currency, Status: SalesOrderPending, IdempotencyKey: "checkout-request-001",
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
	})
	if err != nil { t.Fatalf("create order: %v", err) }
	replayed, err := db.GetSalesOrderByIdempotencyKey(customer.ID, "checkout-request-001")
	if err != nil || replayed.ID != order.ID { t.Fatalf("idempotency lookup failed: order=%+v err=%v", replayed, err) }
	if _, err := db.SaveSalesOrder(SalesOrder{
		CustomerID: customer.ID, PlanID: plan.ID, PlanName: plan.Name, AmountMinor: plan.PriceMinor,
		Currency: plan.Currency, Status: SalesOrderPending, IdempotencyKey: "checkout-request-001",
	}); !errors.Is(err, ErrCommerceIdempotencyKey) { t.Fatalf("duplicate idempotency key accepted: %v", err) }

	payment, err := db.SaveSalesPayment(SalesPayment{
		OrderID: order.ID, CustomerID: customer.ID, Provider: "sandbox", ProviderReference: "sandbox-charge-001",
		AmountMinor: plan.PriceMinor, Currency: plan.Currency, Status: SalesPaymentPending,
	})
	if err != nil { t.Fatalf("create payment: %v", err) }
	payment.Status, payment.VerifiedAt = SalesPaymentSucceeded, time.Now().UTC()
	payment, err = db.SaveSalesPayment(*payment)
	if err != nil { t.Fatalf("mark payment succeeded: %v", err) }
	foundPayment, err := db.GetSalesPaymentByProviderReference("SANDBOX", "sandbox-charge-001")
	if err != nil || foundPayment.ID != payment.ID { t.Fatalf("payment reference lookup failed: %+v %v", foundPayment, err) }

	order.Status, order.PaidAt = SalesOrderPaid, time.Now().UTC()
	order, err = db.SaveSalesOrder(*order)
	if err != nil { t.Fatalf("mark order paid: %v", err) }
	if err := db.SaveClient(Client{ID: "dns-client-001", Name: "Gamer DNS Client", Token: "secret-test-token", AllowedIPs: []string{}, Enabled: true}); err != nil {
		t.Fatalf("create DNS client: %v", err)
	}
	sub, err := db.SaveCustomerSubscription(CustomerSubscription{
		CustomerID: customer.ID, PlanID: plan.ID, OrderID: order.ID, PlanSnapshot: plan, Status: CustomerSubscriptionPending,
	})
	if err != nil { t.Fatalf("create pending subscription: %v", err) }
	sub.Status, sub.ClientID = CustomerSubscriptionActive, "dns-client-001"
	sub, err = db.SaveCustomerSubscription(sub)
	if err != nil { t.Fatalf("activate subscription: %v", err) }
	if sub.StartedAt.IsZero() || sub.ExpiresAt.IsZero() || !sub.ExpiresAt.After(sub.StartedAt) {
		t.Fatalf("subscription dates incorrect: %+v", sub)
	}
	listed, err := db.ListCustomerSubscriptions(customer.ID, 10)
	if err != nil || len(listed) != 1 || listed[0].ID != sub.ID { t.Fatalf("list subscriptions failed: %+v %v", listed, err) }
	if err := db.ValidateCommercialState(); err != nil { t.Fatalf("validate commercial state: %v", err) }
}

func TestCommerceTransitionsRejectFailedOrderBecomingPaid(t *testing.T) {
	db, _ := openCommerceFixture(t)
	customer, plan := createCommerceFixtures(t, db)
	order, err := db.SaveSalesOrder(SalesOrder{
		CustomerID: customer.ID, PlanID: plan.ID, PlanName: plan.Name,
		AmountMinor: plan.PriceMinor, Currency: plan.Currency, Status: SalesOrderPending,
	})
	if err != nil { t.Fatal(err) }
	order.Status = SalesOrderFailed
	order, err = db.SaveSalesOrder(order)
	if err != nil { t.Fatal(err) }
	order.Status = SalesOrderPaid
	if _, err := db.SaveSalesOrder(order); !errors.Is(err, ErrCommerceTransition) {
		t.Fatalf("failed order transitioned to paid: %v", err)
	}
}
