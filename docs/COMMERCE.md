# HyperDNS Storefront (Commerce Foundation)

The public storefront is available at `/store`. It provides Persian/English plan browsing, customer registration and login, order creation, and order history.

## Configure plans

Plan management is intentionally an authenticated management API under the installation's generated admin path:

- `GET /<admin-path>/api/commerce/plans`: list all plans, including disabled plans.
- `POST /<admin-path>/api/commerce/plans`: create or update a plan.

Example request body:

```json
{
  "id": "basic-monthly",
  "name": "Basic monthly",
  "description": "DNS subscription",
  "currency": "USD",
  "price_minor": 999,
  "duration_days": 30,
  "lifetime": false,
  "traffic_limit_gb": 50,
  "traffic_reset_cycle": "monthly",
  "policies": [],
  "enabled": true
}
```

Prices are integer minor units. For USD, `999` means USD 9.99. Use a real currency code and publish prices only after confirming your billing rules.

## Payment and fulfillment status

This phase deliberately does not mark orders as paid, accept arbitrary client-supplied payment confirmation, or activate a DNS client merely because an order was created. Those are money-moving and access-control boundaries. A payment-provider adapter must verify the provider's server-side payment status, amount, currency, order reference, and webhook signature before calling the repository's idempotent confirmation operation. Fulfillment must then provision the matching HyperDNS client and attach its ID to the paid order. Do not expose the repository's payment confirmation function as an unauthenticated HTTP endpoint.

Until a provider is configured, the storefront can create pending orders but cannot collect payment or automatically activate a subscription.

## Routes

- `POST /api/v2/store/auth/register`
- `POST /api/v2/store/auth/login`
- `POST /api/v2/store/auth/logout`
- `GET /api/v2/store/me`
- `GET /api/v2/store/plans`
- `GET, POST /api/v2/store/orders`
- `GET /api/v2/store/orders/{id}`

Customer sessions use HttpOnly cookies and CSRF protection for state-changing requests. The storefront is served on the public subscriber surface; admin plan management remains behind the generated admin path and admin authentication.
