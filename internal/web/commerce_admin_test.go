package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdns/internal/commerce"
	"hyperdns/internal/database"
)

func TestCommerceAdminPlanManagement(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	repo, err := database.NewCommerceRepository(ws.db)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := commerce.NewService(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ws.SetCommerceService(svc)

	body := `{"id":"starter-monthly","name":"Starter","description":"Starter DNS plan","currency":"USD","price_minor":999,"duration_days":30,"lifetime":false,"traffic_limit_gb":25,"traffic_reset_cycle":"monthly","policies":[],"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/commerce/plans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ws.handleCommercePlans(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create plan status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var saved struct {
		Plan database.CommercePlan `json:"plan"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Plan.ID != "starter-monthly" || saved.Plan.PriceMinor != 999 || !saved.Plan.Enabled {
		t.Fatalf("saved plan = %#v", saved.Plan)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/commerce/plans", nil)
	listRec := httptest.NewRecorder()
	ws.handleCommercePlans(listRec, listReq)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "starter-monthly") {
		t.Fatalf("list plans status/body = %d %s", listRec.Code, listRec.Body.String())
	}

	badReq := httptest.NewRequest(http.MethodPost, "/api/commerce/plans", strings.NewReader(body+` {}`))
	badRec := httptest.NewRecorder()
	ws.handleCommercePlans(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("multiple JSON values status = %d", badRec.Code)
	}
}
