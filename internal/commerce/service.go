package commerce

import (
	"errors"
	"fmt"
	"sync"
	"time"

	cryptoutil "hyperdns/internal/crypto"
	"hyperdns/internal/database"
	"hyperdns/internal/service"
)

var (
	ErrInvalidCredentials = errors.New("invalid customer credentials")
	ErrSessionInvalid     = errors.New("customer session is invalid or expired")
)

// Service owns customer-facing commerce rules and in-memory customer sessions.
// It deliberately does not handle payment verification or DNS provisioning.
type Service struct {
	repo        *database.CommerceRepository
	sessions    *service.SessionManager
	mu          sync.RWMutex
	sessionUser map[string]string
	dummyHash   string
}

func NewService(repo *database.CommerceRepository) (*Service, error) {
	if repo == nil {
		return nil, errors.New("commerce service requires a repository")
	}
	dummyHash, err := cryptoutil.HashPassword("hyperdns-invalid-login-dummy-password")
	if err != nil {
		return nil, fmt.Errorf("prepare authentication verifier: %w", err)
	}
	return &Service{
		repo:        repo,
		sessions:    service.NewSessionManagerWithIdle(24*time.Hour, 2*time.Hour),
		sessionUser: make(map[string]string),
		dummyHash:   dummyHash,
	}, nil
}

// Register validates and hashes a password before it reaches encrypted storage.
func (s *Service) Register(email, password, displayName string) (database.CommerceCustomer, error) {
	if err := cryptoutil.ValidatePasswordStrength(email, password); err != nil {
		return database.CommerceCustomer{}, fmt.Errorf("%w: %v", database.ErrCommerceInvalidRecord, err)
	}
	if displayName == "" || len([]rune(displayName)) > 120 {
		return database.CommerceCustomer{}, fmt.Errorf("%w: display_name must contain 1 to 120 characters", database.ErrCommerceInvalidRecord)
	}
	hash, err := cryptoutil.HashPassword(password)
	if err != nil {
		return database.CommerceCustomer{}, fmt.Errorf("hash customer password: %w", err)
	}
	return s.repo.CreateCustomer(database.CommerceCustomer{
		Email:       email,
		DisplayName: displayName,
		Status:      database.CommerceCustomerActive,
	}, hash)
}

// Login uses a dummy verifier for unknown email addresses to reduce account
// enumeration through response-time differences.
func (s *Service) Login(email, password string) (database.CommerceCustomer, string, error) {
	customer, hash, err := s.repo.GetCustomerForAuthentication(email)
	if err != nil {
		if errors.Is(err, database.ErrCommerceNotFound) {
			_ = cryptoutil.VerifyPassword(s.dummyHash, password)
			return database.CommerceCustomer{}, "", ErrInvalidCredentials
		}
		return database.CommerceCustomer{}, "", fmt.Errorf("load customer credentials: %w", err)
	}
	valid := cryptoutil.VerifyPassword(hash, password)
	if !valid || customer.Status != database.CommerceCustomerActive {
		return database.CommerceCustomer{}, "", ErrInvalidCredentials
	}
	token := s.sessions.Create()
	s.mu.Lock()
	s.sessionUser[token] = customer.ID
	s.mu.Unlock()
	return customer, token, nil
}

// Authenticate resolves a live session to an active customer profile.
func (s *Service) Authenticate(token string) (database.CommerceCustomer, error) {
	if token == "" || !s.sessions.Validate(token) {
		return database.CommerceCustomer{}, ErrSessionInvalid
	}
	s.mu.RLock()
	customerID := s.sessionUser[token]
	s.mu.RUnlock()
	if customerID == "" {
		return database.CommerceCustomer{}, ErrSessionInvalid
	}
	customer, err := s.repo.GetCustomer(customerID)
	if err != nil {
		return database.CommerceCustomer{}, fmt.Errorf("load session customer: %w", err)
	}
	if customer.Status != database.CommerceCustomerActive {
		s.Logout(token)
		return database.CommerceCustomer{}, ErrSessionInvalid
	}
	return customer, nil
}

func (s *Service) Logout(token string) {
	if token == "" {
		return
	}
	s.sessions.Delete(token)
	s.mu.Lock()
	delete(s.sessionUser, token)
	s.mu.Unlock()
}

func (s *Service) ListPlans() ([]database.CommercePlan, error) {
	return s.repo.ListPlans(true)
}

func (s *Service) CreateOrder(customerID, planID string) (database.CommerceOrder, error) {
	return s.repo.CreateOrder(customerID, planID)
}

func (s *Service) ListOrders(customerID string, limit int) ([]database.CommerceOrder, error) {
	return s.repo.ListCustomerOrders(customerID, limit)
}

func (s *Service) GetOrder(customerID, orderID string) (database.CommerceOrder, error) {
	order, err := s.repo.GetOrder(orderID)
	if err != nil {
		return database.CommerceOrder{}, err
	}
	if order.CustomerID != customerID {
		return database.CommerceOrder{}, database.ErrCommerceNotFound
	}
	return order, nil
}

func (s *Service) Close() {
	if s != nil && s.sessions != nil {
		s.sessions.Close()
	}
}
