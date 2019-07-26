package billing

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/linkai-io/am/am"
	"github.com/rs/zerolog/log"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/client"
	"github.com/stripe/stripe-go/webhook"
)

type BillingHandlers struct {
	orgClient     am.OrganizationService
	stripeClient  *client.API
	endpointKey   string
	systemContext am.UserContext
}

func New(orgClient am.OrganizationService, systemContext am.UserContext, stripeClient *client.API, endpointKey string) *BillingHandlers {
	return &BillingHandlers{
		orgClient:    orgClient,
		stripeClient: stripeClient,
		endpointKey:  endpointKey,
	}
}

func (h *BillingHandlers) handlePaymentSuccess(ctx context.Context, event stripe.Invoice) error {
	h.orgClient.GetByCID(ctx, h.systemContext, "")
	return nil
}

func (h *BillingHandlers) handlePaymentFailure(ctx context.Context, event stripe.Invoice) error {

	return nil
}

func (h *BillingHandlers) HandleStripe(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error().Err(err).Msg("reading request body failed")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// Pass the request body and Stripe-Signature header to ConstructEvent, along
	// with the webhook signing key.
	// You can find your endpoint's secret in your webhook settings
	event, err := webhook.ConstructEvent(body, req.Header.Get("Stripe-Signature"), h.endpointKey)

	if err != nil {
		log.Error().Err(err).Msg("verifying webhook signature failed")
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}

	// Unmarshal the event data into an appropriate struct depending on its Type
	switch event.Type {
	case "invoice.created":
		var invoice stripe.Invoice
		err := json.Unmarshal(event.Data.Raw, &invoice)
		if err != nil {
			log.Error().Err(err).Msg("parsing webhook JSON failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.handlePaymentSuccess(req.Context(), invoice)
	case "invoice.payment_failed":
		var invoice stripe.Invoice
		err := json.Unmarshal(event.Data.Raw, &invoice)
		if err != nil {
			log.Error().Err(err).Msg("parsing webhook JSON failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.handlePaymentFailure(req.Context(), invoice)
	// ... handle other event types
	default:
		log.Error().Err(err).Msgf("Unexpected event type: %s", event.Type)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
