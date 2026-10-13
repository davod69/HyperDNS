package database

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func commerceFixture(t *testing.T) (*DB, *CommerceRepository) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := Create(path, testCipher(t, 0x7b))
	if err != nil {
		t.Fatalf("Create database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo, err := NewCommerceRepository(db)
	if err != nil {
		t.Fatalf("NewCommerceRepository: %v", err)
	}
	return db, repo
}

func commerceTestPlan() CommercePlan {
	return CommercePlan{
		ID:                "gamer-30d",
		Name:              "Gamer 30 days",
		Description:       "Test package",
		Currency:          "USD",
		PriceMinor:        1299,
		DurationDays:      30,
		TrafficLimitGB:    50,
		TrafficResetCycle: "monthly",
		Policies:          []string{"enable_steam", "enable_riot"},
		Enabled:           true,
	}
}

func commerceTestCustomer(t *testing.T, repo *CommerceRepository) CommerceCustomer {
	t.Helper()
	customer, err := repo.CreateCustomer(CommerceCustomer{
		Email:       "Sales.Test+One@example.com",
		DisplayName: "Test Customer",
	}, "$argon2id$v=19$m=65536,t=3,p=1$test$testencodedhash")
	if err != nil {
		t.Fatalf("CreateCustomer: %v", err)
	}
	return customer
}

func TestCommerceCustomerEmailEncryptedAndIndexed(t *testing.T) {
	db, repo := commerceFixture(t)
	customer := commerceTestCustomer(t, repo)

	got, err := repo.GetCustomer(customer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "sales.test+one@example.com" {
		t.Fatalf("email = %q", got.Email)
	}
	if got.DisplayName != "Test Customer" {
		t.Fatalf("display name = %q", got.DisplayName)
	}

	byEmail, passwordHash, err := repo.GetCustomerForAuthentication(" SALES.TEST+ONE@EXAMPLE.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if byEmail.ID != customer.ID || passwordHash == "" {
		t.Fatalf("authentication lookup = %#v, hash present=%t", byEmail, passwordHash != "")
	}

	if err := db.bolt.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bucketCommerceRoot)
		if root == nil {
			t.Fatal("commerce root bucket missing")
		}
		raw := root.Bucket(bucketCommerceCustomers).Get([]byte(customer.ID))
		if raw == nil {
			t.Fatal("customer record missing")
		}
		if bytes.Contains(raw, []byte("sales.test+one@example.com")) || bytes.Contains(raw, []byte("Test Customer")) {
			t.Fatal("customer PII appears unencrypted in the stored record")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.CreateCustomer(CommerceCustomer{Email: "sales.test+one@example.com"}, "$argon2id$v=19$m=65536,t=3,p=1$test$anotherhash"); !errors.Is(err, ErrCommerceEmailExists) {
		t.Fatalf("duplicate email error = %v", err)
	}
}

func TestCommercePlanValidationAndOrderSnapshot(t *testing.T) {
	_, repo := commerceFixture(t)
	customer := commerceTestCustomer(t, repo)

	plan, err := repo.SavePlan(commerceTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	if plan.CreatedAt.IsZero() || plan.UpdatedAt.IsZero() {
		t.Fatalf("timestamps were not initialized: %#v", plan)
	}

	order, err := repo.CreateOrder(customer.ID, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if order.AmountMinor != 1299 || order.Currency != "USD" || order.Status != CommerceOrderPending {
		t.Fatalf("unexpected order snapshot: %#v", order)
	}

	updated := plan
	updated.PriceMinor = 1999
	updated.Name = "Gamer 30 days v2"
	if _, err := repo.SavePlan(updated); err != nil {
		t.Fatal(err)
	}
	reloaded, err := repo.GetOrder(order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AmountMinor != 1299 || reloaded.PlanName != "Gamer 30 days" {
		t.Fatalf("existing order changed after plan update: %#v", reloaded)
	}

	bad := commerceTestPlan()
	bad.ID = "bad-cycle"
	bad.TrafficResetCycle = "yearly"
	if _, err := repo.SavePlan(bad); !errors.Is(err, ErrCommerceInvalidRecord) {
		t.Fatalf("invalid reset cycle error = %v", err)
	}
	bad = commerceTestPlan()
	bad.ID = "bad-price"
	bad.PriceMinor = -1
	if _, err := repo.SavePlan(bad); !errors.Is(err, ErrCommerceInvalidRecord) {
		t.Fatalf("invalid price error = %v", err)
	}
	bad = commerceTestPlan()
	bad.ID = "unlimited-monthly"
	bad.TrafficLimitGB = 0
	if _, err := repo.SavePlan(bad); !errors.Is(err, ErrCommerceInvalidRecord) {
		t.Fatalf("unlimited plan with reset cycle error = %v", err)
	}
}

func TestCommercePaymentConfirmationIsAtomicAndIdempotent(t *testing.T) {
	_, repo := commerceFixture(t)
	customer := commerceTestCustomer(t, repo)
	plan, err := repo.SavePlan(commerceTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	order, err := repo.CreateOrder(customer.ID, plan.ID)
	if err != nil {
		t.Fatal(err)
	}

	if _, replay, err := repo.ConfirmOrderPayment("testpay", "event-bad", "txn-bad", order.ID, 1298, "USD"); !errors.Is(err, ErrCommerceInvalidRecord) || replay {
		t.Fatalf("bad-amount result replay=%t err=%v", replay, err)
	}
	stillPending, err := repo.GetOrder(order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillPending.Status != CommerceOrderPending {
		t.Fatalf("failed confirmation changed order status to %q", stillPending.Status)
	}

	paid, replay, err := repo.ConfirmOrderPayment("testpay", "event-1", "txn-1", order.ID, 1299, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if replay || paid.Status != CommerceOrderPaid || paid.PaidAt.IsZero() {
		t.Fatalf("first confirmation = status:%q replay:%t", paid.Status, replay)
	}

	duplicate, replay, err := repo.ConfirmOrderPayment("testpay", "event-1", "txn-1", order.ID, 1299, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if !replay || duplicate.Status != CommerceOrderPaid {
		t.Fatalf("duplicate event = status:%q replay:%t", duplicate.Status, replay)
	}

	samePaymentNewEvent, replay, err := repo.ConfirmOrderPayment("testpay", "event-2", "txn-1", order.ID, 1299, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if !replay || samePaymentNewEvent.Status != CommerceOrderPaid {
		t.Fatalf("duplicate provider payment = status:%q replay:%t", samePaymentNewEvent.Status, replay)
	}

	payments, err := repo.ListPayments(order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payments) != 1 || payments[0].ProviderPaymentID != "txn-1" {
		t.Fatalf("payments = %#v", payments)
	}

	fulfilled, err := repo.MarkOrderFulfilled(order.ID, "dns-client-1")
	if err != nil {
		t.Fatal(err)
	}
	if fulfilled.Status != CommerceOrderFulfilled || fulfilled.ClientID != "dns-client-1" {
		t.Fatalf("fulfilled order = %#v", fulfilled)
	}
	again, err := repo.MarkOrderFulfilled(order.ID, "dns-client-1")
	if err != nil || again.Status != CommerceOrderFulfilled {
		t.Fatalf("idempotent fulfillment = %#v err=%v", again, err)
	}
	if _, err := repo.MarkOrderFulfilled(order.ID, "different-client"); !errors.Is(err, ErrCommerceInvalidRecord) {
		t.Fatalf("conflicting fulfillment error = %v", err)
	}
}

func TestCommerceSuspendedCustomerAndDisabledPlanCannotOrder(t *testing.T) {
	_, repo := commerceFixture(t)
	customer := commerceTestCustomer(t, repo)
	plan := commerceTestPlan()
	plan.Enabled = false
	if _, err := repo.SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateOrder(customer.ID, plan.ID); !errors.Is(err, ErrCommercePlanDisabled) {
		t.Fatalf("disabled plan error = %v", err)
	}

	plan.Enabled = true
	if _, err := repo.SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetCustomerStatus(customer.ID, CommerceCustomerSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateOrder(customer.ID, plan.ID); !errors.Is(err, ErrCommerceCustomerSuspended) {
		t.Fatalf("suspended customer error = %v", err)
	}
}

func TestCommerceCustomerAndOrderIsolation(t *testing.T) {
	_, repo := commerceFixture(t)
	one := commerceTestCustomer(t, repo)
	two, err := repo.CreateCustomer(CommerceCustomer{
		Email:       "other@example.org",
		DisplayName: "Other Customer",
	}, "$argon2id$v=19$m=65536,t=3,p=1$test$anotherencodedhash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SavePlan(commerceTestPlan()); err != nil {
		t.Fatal(err)
	}
	order, err := repo.CreateOrder(one.ID, "gamer-30d")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CancelOrder(order.ID, two.ID); !errors.Is(err, ErrCommerceNotFound) {
		t.Fatalf("foreign order cancel error = %v", err)
	}
	if _, err := repo.ListCustomerOrders(two.ID, 10); err != nil {
		t.Fatal(err)
	}
	orders, err := repo.ListCustomerOrders(one.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 || orders[0].ID != order.ID {
		t.Fatalf("customer orders = %#v", orders)
	}
	if _, err := repo.ListCustomerOrders(one.ID, 501); !errors.Is(err, ErrCommerceInvalidRecord) {
		t.Fatalf("invalid list limit error = %v", err)
	}
}

func TestCommerceRepositoryRequiresOpenEncryptedDatabase(t *testing.T) {
	if _, err := NewCommerceRepository(nil); err == nil {
		t.Fatal("nil database should be rejected")
	}
	path := filepath.Join(t.TempDir(), "plain.db")
	db, err := Create(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := NewCommerceRepository(db); err == nil {
		t.Fatal("repository without master-key cipher should be rejected")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCommerceSchemaVersionIsRecordedAndChecked(t *testing.T) {
	db, repo := commerceFixture(t)
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bucketCommerceRoot)
		if root == nil {
			t.Fatal("commerce root bucket missing")
		}
		if got := string(root.Get(commerceSchemaVersionKey)); got != "1" {
			t.Fatalf("schema version = %q, want 1", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = repo

	// Opening another repository instance against a database from the current
	// schema is idempotent and leaves the version and buckets intact.
	reopened, err := NewCommerceRepository(db)
	if err != nil || reopened == nil {
		t.Fatalf("reopen current schema: repo=%v err=%v", reopened, err)
	}
}

func TestCommerceSchemaRefusesFutureVersionWithoutAddingBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	db, err := Create(path, testCipher(t, 0x7c))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists(bucketCommerceRoot)
		if err != nil {
			return err
		}
		if err := root.Put(commerceSchemaVersionKey, []byte("999")); err != nil {
			return err
		}
		_, err = root.CreateBucketIfNotExists(bucketCommercePlans)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCommerceRepository(db); err == nil {
		t.Fatal("future schema version must be refused")
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		root := tx.Bucket(bucketCommerceRoot)
		if got := string(root.Get(commerceSchemaVersionKey)); got != "999" {
			t.Fatalf("future schema version was overwritten: %q", got)
		}
		if root.Bucket(bucketCommerceCustomers) != nil {
			t.Fatal("future schema refusal still created customer buckets")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
