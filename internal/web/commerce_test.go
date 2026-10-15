package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"hyperdns/internal/commerce"
	cryptoutil "hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

func newCommerceAPITest(t *testing.T) (*commerceAPI, *database.CommerceRepository) {
	t.Helper()
	cipher, err := cryptoutil.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Create(filepath.Join(t.TempDir(), "commerce.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo, err := database.NewCommerceRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := commerce.NewService(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return &commerceAPI{service: svc, limiter: service.NewLoginAttemptTracker()}, repo
}

func requestCommerce(api *commerceAPI, method, path, body string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	api.handler().ServeHTTP(rec, req)
	return rec
}

func (api *commerceAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/store/auth/register", api.register)
	mux.HandleFunc("/api/v2/store/auth/login", api.login)
	mux.HandleFunc("/api/v2/store/auth/logout", api.logout)
	mux.HandleFunc("/api/v2/store/me", api.me)
	mux.HandleFunc("/api/v2/store/plans", api.plans)
	mux.HandleFunc("/api/v2/store/orders", api.orders)
	mux.HandleFunc("/api/v2/store/orders/", api.order)
	return mux
}

func TestCommerceAPIRegisterLoginAndMe(t *testing.T) {
	api, _ := newCommerceAPITest(t)
	register := requestCommerce(api, http.MethodPost, "/api/v2/store/auth/register",
		`{"email":"Buyer@example.com","password":"Str0ng-unique-password-2026","display_name":"Buyer"}`, nil, "")
	if register.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body=%s", register.Code, register.Body.String())
	}
	if strings.Contains(register.Body.String(), "password_hash") || strings.Contains(register.Body.String(), "Str0ng-unique-password") {
		t.Fatalf("registration response exposed a credential: %s", register.Body.String())
	}
	duplicate := requestCommerce(api, http.MethodPost, "/api/v2/store/auth/register",
		`{"email":"buyer@example.com","password":"Str0ng-unique-password-2026","display_name":"Buyer"}`, nil, "")
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, body=%s", duplicate.Code, duplicate.Body.String())
	}
	login := requestCommerce(api, http.MethodPost, "/api/v2/store/auth/login",
		`{"email":"BUYER@example.com","password":"Str0ng-unique-password-2026"}`, nil, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", login.Code, login.Body.String())
	}
	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		switch cookie.Name {
		case commerceSessionCookie:
			sessionCookie = cookie
		case commerceCSRFCookie:
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || csrfCookie == nil || csrfCookie.HttpOnly {
		t.Fatalf("session/CSRF cookie attributes are unsafe: session=%#v csrf=%#v", sessionCookie, csrfCookie)
	}
	me := requestCommerce(api, http.MethodGet, "/api/v2/store/me", "", []*http.Cookie{sessionCookie}, "")
	if me.Code != http.StatusOK {
		t.Fatalf("me status = %d, body=%s", me.Code, me.Body.String())
	}
	unauthenticated := requestCommerce(api, http.MethodGet, "/api/v2/store/me", "", nil, "")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated me status = %d", unauthenticated.Code)
	}
	logout := requestCommerce(api, http.MethodPost, "/api/v2/store/auth/logout", "", []*http.Cookie{sessionCookie, csrfCookie}, csrfCookie.Value)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, body=%s", logout.Code, logout.Body.String())
	}
	afterLogout := requestCommerce(api, http.MethodGet, "/api/v2/store/me", "", []*http.Cookie{sessionCookie}, "")
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d", afterLogout.Code)
	}
}

func TestCommerceAPIPlansAndOrdersEnforceCSRFAndOwnership(t *testing.T) {
	api, repo := newCommerceAPITest(t)
	first, err := api.service.Register("first@example.com", "Str0ng-unique-password-2026", "First")
	if err != nil {
		t.Fatal(err)
	}
	second, err := api.service.Register("second@example.com", "An0ther-unique-password-2026", "Second")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repo.SavePlan(database.CommercePlan{
		ID: "basic-monthly", Name: "Basic monthly", Currency: "USD",
		PriceMinor: 1299, DurationDays: 30, TrafficLimitGB: 50,
		TrafficResetCycle: "monthly", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := api.service.Login(first.Email, "Str0ng-unique-password-2026")
	if err != nil {
		t.Fatal(err)
	}
	csrf := "known-test-csrf"
	cookies := []*http.Cookie{
		{Name: commerceSessionCookie, Value: token},
		{Name: commerceCSRFCookie, Value: csrf},
	}
	plans := requestCommerce(api, http.MethodGet, "/api/v2/store/plans", "", nil, "")
	if plans.Code != http.StatusOK || !strings.Contains(plans.Body.String(), plan.ID) {
		t.Fatalf("plans response = %d %s", plans.Code, plans.Body.String())
	}
	noCSRF := requestCommerce(api, http.MethodPost, "/api/v2/store/orders", `{"plan_id":"basic-monthly"}`, cookies, "")
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("order without CSRF status = %d", noCSRF.Code)
	}
	created := requestCommerce(api, http.MethodPost, "/api/v2/store/orders", `{"plan_id":"basic-monthly"}`, cookies, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("create order status = %d, body=%s", created.Code, created.Body.String())
	}
	var payload struct {
		Order database.CommerceOrder `json:"order"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Order.AmountMinor != 1299 || payload.Order.Status != database.CommerceOrderPending {
		t.Fatalf("order snapshot = %#v", payload.Order)
	}
	foreign, err := api.service.GetOrder(second.ID, payload.Order.ID)
	if err == nil || foreign.ID != "" {
		t.Fatalf("cross-customer order lookup unexpectedly succeeded: %#v, %v", foreign, err)
	}
	get := requestCommerce(api, http.MethodGet, "/api/v2/store/orders/"+payload.Order.ID, "", cookies, "")
	if get.Code != http.StatusOK {
		t.Fatalf("order get status = %d, body=%s", get.Code, get.Body.String())
	}
}

func TestCommerceAPIRejectsUnknownFieldsAndWrongMethods(t *testing.T) {
	api, _ := newCommerceAPITest(t)
	bad := requestCommerce(api, http.MethodPost, "/api/v2/store/auth/register",
		`{"email":"buyer@example.com","password":"Str0ng-unique-password-2026","display_name":"Buyer","is_admin":true}`, nil, "")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", bad.Code)
	}
	wrongMethod := requestCommerce(api, http.MethodDelete, "/api/v2/store/plans", "", nil, "")
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d", wrongMethod.Code)
	}
}
