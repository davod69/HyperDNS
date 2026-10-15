package commerce

import (
	"errors"
	"path/filepath"
	"testing"

	cryptoutil "hyperdns/internal/crypto"
	"hyperdns/internal/database"
)

func testService(t *testing.T) (*Service, *database.CommerceRepository) {
	t.Helper()
	cipher, err := cryptoutil.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Create(filepath.Join(t.TempDir(), "data.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo, err := database.NewCommerceRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc, repo
}

func TestRegisterLoginAndLogout(t *testing.T) {
	svc, _ := testService(t)
	if _, err := svc.Register("a@example.com", "short", "Customer"); !errors.Is(err, database.ErrCommerceInvalidRecord) {
		t.Fatalf("weak password error = %v", err)
	}
	customer, err := svc.Register("A@example.com", "Str0ng-unique-password-2026", "Customer A")
	if err != nil {
		t.Fatal(err)
	}
	if customer.Email != "a@example.com" {
		t.Fatalf("email was not normalized: %q", customer.Email)
	}
	if _, err := svc.Register("a@example.com", "Str0ng-unique-password-2026", "Duplicate"); !errors.Is(err, database.ErrCommerceEmailExists) {
		t.Fatalf("duplicate registration error = %v", err)
	}
	if _, _, err := svc.Login("a@example.com", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	loggedIn, token, err := svc.Login("A@EXAMPLE.COM", "Str0ng-unique-password-2026")
	if err != nil {
		t.Fatal(err)
	}
	if loggedIn.ID != customer.ID || token == "" {
		t.Fatalf("login customer/token = %#v, token present=%t", loggedIn, token != "")
	}
	got, err := svc.Authenticate(token)
	if err != nil || got.ID != customer.ID {
		t.Fatalf("Authenticate = %#v, %v", got, err)
	}
	svc.Logout(token)
	if _, err := svc.Authenticate(token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session after logout = %v", err)
	}
}

func TestOrdersSnapshotPlanAndEnforceOwnership(t *testing.T) {
	svc, repo := testService(t)
	first, err := svc.Register("first@example.com", "Str0ng-unique-password-2026", "First Customer")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Register("second@example.com", "An0ther-unique-password-2026", "Second Customer")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repo.SavePlan(database.CommercePlan{
		ID: "basic-monthly", Name: "Basic monthly", Description: "A test plan",
		Currency: "USD", PriceMinor: 1299, DurationDays: 30,
		TrafficLimitGB: 50, TrafficResetCycle: "monthly", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	order, err := svc.CreateOrder(first.ID, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan.Name, plan.PriceMinor = "Renamed plan", 9999
	if _, err := repo.SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	snapshot, err := svc.GetOrder(first.ID, order.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PlanName != "Basic monthly" || snapshot.AmountMinor != 1299 {
		t.Fatalf("order snapshot changed: %#v", snapshot)
	}
	if _, err := svc.GetOrder(second.ID, order.ID); !errors.Is(err, database.ErrCommerceNotFound) {
		t.Fatalf("cross-customer order lookup = %v", err)
	}
	orders, err := svc.ListOrders(first.ID, 50)
	if err != nil || len(orders) != 1 || orders[0].ID != order.ID {
		t.Fatalf("customer orders = %#v, %v", orders, err)
	}
}
