package billing_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/linkai-io/am/mock"
	"github.com/linkai-io/am/pkg/secrets"
	"github.com/linkai-io/frontend/fetest"
	"github.com/linkai-io/frontend/mock/femock"
	"github.com/stripe/stripe-go/client"
	"github.com/stripe/stripe-go/webhook"
)

var subscriptionMessage = `{
      "id": "cs_test_xmpFWYi9XgxUSIx12G3VNp8YI0DCwn5KDPwPy85tKaI3ictC0Lw6NuCo",
      "object": "checkout.session",
      "billing_address_collection": "required",
      "cancel_url": "https://console.linkai.io/incoming/canceled",
      "client_reference_id": "somerandomvalue",
      "customer": "cus_FWZdZvoNltPyoR",
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
      "subscription": "sub_FWZdlA6FprXyiT",
      "success_url": "https://console.linkai.io/incoming/success"
    }
  }`
var subSign = `t=1564397639,v1=0a892a62c471f950b452b18f19862f1a3b58d0705230a467a3929aed4f2373c6,v0=4f8e01b93b78a2657adce767d1b4f2e92f4e3b802c0d9edcb8d66a00fc6f5b38`

func TestSuccess(t *testing.T) {

	secret := secrets.NewSecretsCache("local", "")
	stripeKey, err := secret.GetSecureString(fmt.Sprintf("/am/%s/billing/stripe/key", "local"))
	if err != nil {
		t.Fatalf("error reading stripe key %v", err)
	}

	sc := &client.API{}
	sc.Init(stripeKey, nil)

	orgClient := &mock.OrganizationService{}
	billingHandlers := femock.MockWebHooks("local", "us-east-1", sc, orgClient, secret)
	billingHandlers.SigVerifier = webhook.ConstructEventIgnoringTolerance
	r := chi.NewRouter()
	r.Route("/incoming", func(r chi.Router) {
		r.Post("/stripe_events", billingHandlers.HandleStripe)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()
	headers := make(http.Header)
	headers.Add("Stripe-Signature", subSign)

	rr, _ := fetest.RouterTestRequestWithHeaders(t, ts, "POST", "/incoming/stripe_events", headers, strings.NewReader(subscriptionMessage))
	// Check the status code is what we expect.
	if status := rr.StatusCode; status != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

}
