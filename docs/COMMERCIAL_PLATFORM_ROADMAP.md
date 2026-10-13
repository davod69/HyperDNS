# HyperDNS Commercial Platform Roadmap

This document tracks the commercial-product work built on top of HyperDNS.
The resolver's existing Client model remains the enforcement unit; a separate
commerce model owns customer identity, plans, orders, payment events,
subscriptions and commercial audit events.

## Baseline audit

- Existing DNS engine: Go single-binary service.
- Existing persistence: embedded bbolt database, encrypted sensitive fields,
  and explicit startup validation/migration.
- Existing access unit: a DNS Client with IP binding, expiry, quotas, quota
  reset cycle, policy overrides and subscriber registration credentials.
- Existing management surface: REST API v2, admin dashboard, telemetry and a
  Persian/English localization dictionary.
- Existing Telegram integration is an administrator controller/provisioner,
  not a customer checkout bot that records orders and verified payments.
- Existing installer intentionally performs a fresh install after archiving an
  old installation. It must not be reused as a data-preserving upgrade flow.

## Implementation phases

1. **Commercial data foundation** — independent customer, plan, order, payment,
   subscription and audit records; encrypted storage; uniqueness indexes;
   explicit state transitions; startup validation; tests.
2. **Customer authentication and portal** — password hashing using existing
   security primitives, login/session handling, customer-only order/subscription
   views, disabled-account enforcement and CSRF/session protections.
3. **Checkout and payment adapter** — provider-neutral invoice lifecycle,
   idempotent callbacks, signature verification, amount/currency validation,
   replay protection and sandbox tests. A production provider is chosen before
   enabling live charges.
4. **Provisioning** — create a DNS Client only after verified payment; snapshot
   purchased plan settings; expire/suspend service according to subscription
   status; make provisioning and renewal idempotent.
5. **Telegram** — retain the admin controller but update it to the current API,
   then add a separate customer workflow for account linking, invoices,
   subscription status and renewal notifications.
6. **Dashboard and bilingual UX** — manage plans, customers, orders, payments,
   subscriptions, audit events and commercial monitoring in Persian and English.
7. **Multi-node control plane** — keep the first deployment single-node, while
   defining node identity, authenticated control channels, health state and
   deterministic subscription assignment.
8. **Install and operations** — add a non-destructive upgrade path, backup
   validation/restore tests, systemd integration, secret-safe example configs,
   smoke tests and Ubuntu 22.04/24.04 CI coverage.

## Security and data invariants

- Commerce records are encrypted using the existing master key. Email indexes
  use a keyed blind index rather than a plaintext email key.
- Money uses integer minor units and a currency code, never floating-point
  arithmetic.
- A store customer and its DNS Client are separate records joined through a
  commercial subscription.
- Order prices and plan benefits are snapshotted at purchase.
- Order/payment/subscription lifecycle transitions are checked centrally.
- A callback is not proof of payment by itself; provider authenticity and paid
  amount/currency must be verified by the payment adapter.
- Installer changes must preserve the complete data.db + master.key pair.
- Never commit live credentials, API keys, bot tokens or customer data.

## Delivery status

- [x] Repository audit
- [x] Commercial data model and encrypted repositories
- [ ] Customer authentication / portal
- [ ] Provider integration and verified checkout
- [ ] Provisioning and renewals
- [ ] Customer Telegram workflow
- [ ] Commercial admin UI and reporting
- [ ] Multi-node control plane
- [ ] Data-preserving installer / upgrade
