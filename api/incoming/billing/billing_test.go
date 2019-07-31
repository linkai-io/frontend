package billing_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/fetest"
	"github.com/linkai-io/frontend/mock/femock"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/client"
)

var subscriptionMessage = `{
  "id": "evt_1F1numDU5nzuhrj2rwI9Z52w",
  "object": "event",
  "api_version": "2018-05-21",
  "created": 1564464623,
  "data": {
    "object": {
      "id": "cs_test_3IFMNAGQUYoB5vEGItkOgviEbmMeQVtFbqhVECJnqeBw9ucidPiwUAmK",
      "object": "checkout.session",
      "billing_address_collection": "required",
      "cancel_url": "https://console.linkai.io/incoming/canceled",
      "client_reference_id": "somerandomvalue",
      "customer": "cus_FWreLjK3DSiaje",
      "customer_email": "test@somerandomvalue.com",
      "display_items": [
        {
          "amount": 24900,
          "currency": "usd",
          "plan": {
            "id": "plan_FTszjACnOXAzvO",
            "object": "plan",
            "active": true,
            "aggregate_usage": null,
            "amount": 24900,
            "billing_scheme": "per_unit",
            "created": 1563777690,
            "currency": "usd",
            "interval": "month",
            "interval_count": 1,
            "livemode": false,
            "metadata": {
              "tlds": "1",
              "hosts": "100",
              "hours": "12",
              "size": "small"
            },
            "nickname": "Beta Monthly Small",
            "product": "prod_FTsv5Pepz7V9f1",
            "tiers": null,
            "tiers_mode": null,
            "transform_usage": null,
            "trial_period_days": null,
            "usage_type": "licensed"
          },
          "quantity": 1,
          "type": "plan"
        }
      ],
      "livemode": false,
      "locale": null,
      "payment_intent": null,
      "payment_method_types": [
        "card"
      ],
      "submit_type": null,
      "subscription": "sub_FWre6YYyYb84WD",
      "success_url": "https://console.linkai.io/incoming/success"
    }
  },
  "livemode": false,
  "pending_webhooks": 1,
  "request": {
    "id": "req_apoTns6E0YcdaN",
    "idempotency_key": null
  },
  "type": "checkout.session.completed"
}`

func TestSuccess(t *testing.T) {

	secret := secrets.NewSecretsCache("local", "")
	stripeKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/key", "local"))
	if err != nil {
		t.Fatalf("error reading stripe key %v", err)
	}

	sc := &client.API{}
	sc.Init(stripeKey, nil)

	orgClient := femock.MockOrgClient()
	billingHandlers := femock.MockWebHooks("local", "us-east-1", sc, orgClient, secret)
	// ignore sig validation
	billingHandlers.SigVerifier = func(payload []byte, header, secret string) (stripe.Event, error) {
		e := stripe.Event{}
		if err := json.Unmarshal(payload, &e); err != nil {
			return e, fmt.Errorf("Failed to parse webhook body json: %s", err.Error())
		}

		return e, nil
	}
	r := chi.NewRouter()
	r.Route("/incoming", func(r chi.Router) {
		r.Post("/stripe_events", billingHandlers.HandleStripe)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()
	headers := make(http.Header)

	rr, _ := fetest.RouterTestRequestWithHeaders(t, ts, "POST", "/incoming/stripe_events", headers, strings.NewReader(subscriptionMessage))
	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

  orgClient.GetByCID(context.Background(), )
}
