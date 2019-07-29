package billing

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/rs/zerolog/log"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/client"
	"github.com/stripe/stripe-go/webhook"
)

var (
	ErrInvalidCustomerID = errors.New("invalid customer id")
	ErrInvalidDisplayNum = errors.New("invalid number of display items in events")
)

type SigFn func(payload []byte, header string, secret string) (stripe.Event, error)

type BillingHandlers struct {
	orgClient     am.OrganizationService
	stripeClient  *client.API
	endpointKey   string
	systemContext am.UserContext
	SigVerifier   SigFn
}

func New(orgClient am.OrganizationService, systemContext am.UserContext, stripeClient *client.API, endpointKey string) *BillingHandlers {
	return &BillingHandlers{
		orgClient:    orgClient,
		stripeClient: stripeClient,
		endpointKey:  endpointKey,
		SigVerifier:  webhook.ConstructEvent,
	}
}

func (h *BillingHandlers) handlePaymentSuccess(ctx context.Context, session stripe.CheckoutSession) error {
	if session.Customer == nil || session.Customer.ID == "" {
		return ErrInvalidCustomerID
	}

	if len(session.DisplayItems) != 1 {
		return ErrInvalidDisplayNum
	}

	_, org, err := h.orgClient.GetByCID(ctx, h.systemContext, session.ClientReferenceID)
	if err != nil {
		log.Error().Err(err).Str("orgCID", session.ClientReferenceID).Msg("failed to get org by client id from checkout session")
		return err
	}

	sub, err := h.stripeClient.Subscriptions.Get(session.Subscription.ID, &stripe.SubscriptionParams{})
	if err != nil {
		log.Error().Err(err).Str("orgCID", session.ClientReferenceID).Str("subID", session.Subscription.ID).Msg("failed to get subscription details from checkout session")
		return err
	}

	// convert sec to nsec
	periodEnd := time.Unix(sub.CurrentPeriodEnd, 0)

	org.BillingSubscriptionID = session.Subscription.ID
	org.BillingPlanID = session.DisplayItems[0].Plan.ID
	org.BillingPlanType = "stripe"
	org.PaymentRequiredTimestamp = periodEnd.UnixNano()

	proxyContext := am.ProxyUserContext(org.OrgID, h.systemContext)
	proxyContext.OrgCID = org.OrgCID
	proxyContext.OrgStatusID = org.StatusID
	proxyContext.SubscriptionID = org.SubscriptionID
	_, err = h.orgClient.Update(ctx, proxyContext, org)
	return err
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
	log.Info().Str("sig", req.Header.Get("Stripe-Signature")).Msg("signing header")
	if err != nil {
		log.Error().Err(err).Msg("verifying webhook signature failed")
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}

	log.Info().Msgf("incoming webhook event %s", event.Data.Raw)
	// Unmarshal the event data into an appropriate struct depending on its Type
	switch event.Type {
	case "checkout.session.completed":
		var session stripe.CheckoutSession
		err := json.Unmarshal(event.Data.Raw, &session)
		if err != nil {
			log.Error().Err(err).Msg("parsing webhook JSON failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Info().Msgf("incoming webhook invoice %#v", session)
		if err := h.handlePaymentSuccess(req.Context(), session); err != nil {
			log.Error().Err(err).Msg("failed to handle checkout.session.completed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	//case "customer.subscription.deleted":
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
