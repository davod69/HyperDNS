package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"hyperdns/internal/database"
)

func (ws *WebServer) handleCommercePlans(w http.ResponseWriter, r *http.Request) {
	if ws.commerce == nil {
		http.Error(w, "commerce unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		plans, err := ws.commerce.ListAllPlans()
		if err != nil {
			http.Error(w, "could not list plans", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"plans": plans})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var plan database.CommercePlan
		if err := dec.Decode(&plan); err != nil {
			http.Error(w, "invalid plan JSON", http.StatusBadRequest)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err == nil {
			http.Error(w, "expected one JSON object", http.StatusBadRequest)
			return
		}
		plan.ID = strings.TrimSpace(plan.ID)
		saved, err := ws.commerce.SavePlan(plan)
		if err != nil {
			if errors.Is(err, database.ErrCommerceInvalidRecord) || errors.Is(err, database.ErrCommerceEmailExists) {
				http.Error(w, "invalid plan", http.StatusBadRequest)
				return
			}
			http.Error(w, "could not save plan", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"plan": saved})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

