package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"hyperdns/internal/commerce"
	"hyperdns/internal/database"
	"hyperdns/internal/netutil"
	"hyperdns/internal/service"
)

const (
	commerceSessionCookie = "hdns_customer_session"
	commerceCSRFCookie    = "hdns_customer_csrf"
	commerceRequestLimit  = 1 << 20
)

type commerceAPI struct {
	service *commerce.Service
	limiter *service.LoginAttemptTracker
	secure  bool
}

type commerceError struct {
	Error commerceErrorDetail `json:"error"`
}

type commerceErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeCommerceError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(commerceError{Error: commerceErrorDetail{Code: code, Message: message}})
}

func writeCommerceJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeCommerceJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, commerceRequestLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeCommerceError(w, http.StatusBadRequest, "invalid_request", "The request body must be a valid JSON object.")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeCommerceError(w, http.StatusBadRequest, "invalid_request", "The request must contain exactly one JSON value.")
		return false
	}
	return true
}

func (ws *WebServer) SetCommerceService(svc *commerce.Service) {
	if ws == nil {
		return
	}
	ws.commerce = svc
}

func (ws *WebServer) commerceHandler() http.Handler {
	api := &commerceAPI{
		service: ws.commerce,
		limiter: ws.commerceLimiter,
		secure:  ws.panelHTTPS(),
	}
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

func (api *commerceAPI) ready(w http.ResponseWriter) bool {
	if api.service == nil {
		writeCommerceError(w, http.StatusServiceUnavailable, "store_unavailable", "The customer store is not available.")
		return false
	}
	return true
}

func (api *commerceAPI) method(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeCommerceError(w, http.StatusMethodNotAllowed, "method_not_allowed", "This HTTP method is not allowed for this endpoint.")
		return false
	}
	return true
}

func (api *commerceAPI) setSession(w http.ResponseWriter, r *http.Request, token string) bool {
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return false
	}
	csrf := hex.EncodeToString(csrfBytes)
	http.SetCookie(w, &http.Cookie{
		Name: commerceSessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: api.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 24 * 60 * 60,
	})
	http.SetCookie(w, &http.Cookie{
		Name: commerceCSRFCookie, Value: csrf, Path: "/", HttpOnly: false,
		Secure: api.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 24 * 60 * 60,
	})
	return true
}

func (api *commerceAPI) clearSession(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{commerceSessionCookie, commerceCSRFCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", HttpOnly: name == commerceSessionCookie,
			Secure: api.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1,
		})
	}
}

func (api *commerceAPI) csrfValid(r *http.Request) bool {
	cookie, err := r.Cookie(commerceCSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && len(header) == len(cookie.Value) &&
		subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

func (api *commerceAPI) requireCustomer(w http.ResponseWriter, r *http.Request) (database.CommerceCustomer, string, bool) {
	if !api.ready(w) {
		return database.CommerceCustomer{}, "", false
	}
	cookie, err := r.Cookie(commerceSessionCookie)
	if err != nil || cookie.Value == "" {
		writeCommerceError(w, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
		return database.CommerceCustomer{}, "", false
	}
	customer, err := api.service.Authenticate(cookie.Value)
	if err != nil {
		api.clearSession(w, r)
		writeCommerceError(w, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
		return database.CommerceCustomer{}, "", false
	}
	return customer, cookie.Value, true
}

func (api *commerceAPI) register(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodPost) || !api.ready(w) {
		return
	}
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decodeCommerceJSON(w, r, &req) {
		return
	}
	customer, err := api.service.Register(req.Email, req.Password, req.DisplayName)
	if err != nil {
		if errors.Is(err, database.ErrCommerceEmailExists) {
			writeCommerceError(w, http.StatusConflict, "email_exists", "An account with this email already exists.")
			return
		}
		if errors.Is(err, database.ErrCommerceInvalidRecord) {
			writeCommerceError(w, http.StatusBadRequest, "invalid_request", "The email, password, or display name does not meet the requirements.")
			return
		}
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	writeCommerceJSON(w, http.StatusCreated, map[string]any{"customer": customer})
}

func (api *commerceAPI) login(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodPost) || !api.ready(w) {
		return
	}
	ip := netutil.ClientIP(r)
	if api.limiter != nil && api.limiter.IsBlocked(ip) {
		writeCommerceError(w, http.StatusTooManyRequests, "rate_limited", "Too many failed login attempts. Try again later.")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeCommerceJSON(w, r, &req) {
		return
	}
	customer, token, err := api.service.Login(req.Email, req.Password)
	if err != nil {
		if api.limiter != nil {
			api.limiter.RecordFailure(ip)
		}
		if errors.Is(err, commerce.ErrInvalidCredentials) {
			writeCommerceError(w, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.")
			return
		}
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	if api.limiter != nil {
		api.limiter.RecordSuccess(ip)
	}
	if !api.setSession(w, r, token) {
		api.service.Logout(token)
		return
	}
	writeCommerceJSON(w, http.StatusOK, map[string]any{"customer": customer})
}

func (api *commerceAPI) logout(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodPost) {
		return
	}
	_, token, ok := api.requireCustomer(w, r)
	if !ok {
		return
	}
	if !api.csrfValid(r) {
		writeCommerceError(w, http.StatusForbidden, "csrf_failed", "The CSRF token is missing or invalid.")
		return
	}
	api.service.Logout(token)
	api.clearSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (api *commerceAPI) me(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodGet) {
		return
	}
	customer, _, ok := api.requireCustomer(w, r)
	if !ok {
		return
	}
	writeCommerceJSON(w, http.StatusOK, map[string]any{"customer": customer})
}

func (api *commerceAPI) plans(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodGet) || !api.ready(w) {
		return
	}
	plans, err := api.service.ListPlans()
	if err != nil {
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	writeCommerceJSON(w, http.StatusOK, map[string]any{"plans": plans})
}

func (api *commerceAPI) orders(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v2/store/orders" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeCommerceError(w, http.StatusMethodNotAllowed, "method_not_allowed", "This HTTP method is not allowed for this endpoint.")
		return
	}
	customer, _, ok := api.requireCustomer(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if !api.csrfValid(r) {
			writeCommerceError(w, http.StatusForbidden, "csrf_failed", "The CSRF token is missing or invalid.")
			return
		}
		var req struct {
			PlanID string `json:"plan_id"`
		}
		if !decodeCommerceJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.PlanID) == "" || len(req.PlanID) > 128 {
			writeCommerceError(w, http.StatusBadRequest, "invalid_request", "plan_id is required.")
			return
		}
		order, err := api.service.CreateOrder(customer.ID, req.PlanID)
		switch {
		case err == nil:
			writeCommerceJSON(w, http.StatusCreated, map[string]any{"order": order})
		case errors.Is(err, database.ErrCommerceNotFound), errors.Is(err, database.ErrCommercePlanDisabled):
			writeCommerceError(w, http.StatusBadRequest, "plan_unavailable", "The selected plan is not available.")
		case errors.Is(err, database.ErrCommerceCustomerSuspended):
			writeCommerceError(w, http.StatusForbidden, "account_suspended", "This account cannot create orders.")
		default:
			writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		}
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeCommerceError(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 100.")
			return
		}
		limit = n
	}
	orders, err := api.service.ListOrders(customer.ID, limit)
	if err != nil {
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	writeCommerceJSON(w, http.StatusOK, map[string]any{"orders": orders})
}

func (api *commerceAPI) order(w http.ResponseWriter, r *http.Request) {
	if !api.method(w, r, http.MethodGet) {
		return
	}
	customer, _, ok := api.requireCustomer(w, r)
	if !ok {
		return
	}
	orderID := strings.TrimPrefix(r.URL.Path, "/api/v2/store/orders/")
	if orderID == "" || strings.Contains(orderID, "/") {
		http.NotFound(w, r)
		return
	}
	order, err := api.service.GetOrder(customer.ID, orderID)
	if errors.Is(err, database.ErrCommerceNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeCommerceError(w, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return
	}
	writeCommerceJSON(w, http.StatusOK, map[string]any{"order": order})
}
