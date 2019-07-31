package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
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
	ErrNoMetadataKey     = errors.New("key not found in metadata map")
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
		orgClient:     orgClient,
		systemContext: systemContext,
		stripeClient:  stripeClient,
		endpointKey:   endpointKey,
		SigVerifier:   webhook.ConstructEvent,
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

	return h.UpdateSubscription(ctx, org, sub)
}

func (h *BillingHandlers) UpdateSubscription(ctx context.Context, org *am.Organization, sub *stripe.Subscription) error {
	// some what of a hack since we don't have the proper userid looked up from the users table, but
	// the org service only uses user context orgID to validate.
	proxyContext := am.ProxyUserContext(org.OrgID, h.systemContext)
	proxyContext.OrgCID = org.OrgCID
	proxyContext.OrgStatusID = org.StatusID
	proxyContext.SubscriptionID = org.SubscriptionID
	// convert sec to nsec
	periodEnd := time.Unix(sub.CurrentPeriodEnd, 0)

	tlds, err := GetMetadataInt32(sub.Plan.Metadata, "tlds")
	if err != nil {
		return err
	}

	hosts, err := GetMetadataInt32(sub.Plan.Metadata, "hosts")
	if err != nil {
		return err
	}

	var subID int32
	size := sub.Plan.Metadata["size"]
	switch size {
	case "small":
		subID = am.SubscriptionMonthlySmall
	case "medium":
		subID = am.SubscriptionMonthlyMedium
	case "large":
		subID = am.SubscriptionEnterprise
	}

	// new plan
	if org.BillingSubscriptionID == "" {
		//hours, err := GetMetadataInt32(sub.Metadata, "hours")
		org.LimitTLD = tlds
		org.LimitHosts = hosts
	}
	org.SubscriptionID = subID
	org.BillingSubscriptionID = sub.ID
	org.BillingPlanID = sub.Plan.ID
	org.BillingPlanType = "stripe"
	org.PaymentRequiredTimestamp = periodEnd.UnixNano()

	_, err = h.orgClient.Update(ctx, proxyContext, org)
	return err
}

func (h *BillingHandlers) handleReoccurringPaymentSuccess(ctx context.Context, event stripe.Invoice) error {
	return nil
}

func (h *BillingHandlers) handlePaymentFailure(ctx context.Context, event stripe.Invoice) error {
	return nil
}

func (h *BillingHandlers) handleSubscriptionUpdated(ctx context.Context, event stripe.Invoice) error {
	return nil
}

func (h *BillingHandlers) getOrgByBillingSubID(ctx context.Context, subID string) (*am.Organization, error) {

	if subID == "" {
		return nil, errors.New("subscription id was empty")
	}

	filter := &am.OrgFilter{
		Start:   0,
		Limit:   2,
		Filters: &am.FilterType{},
	}

	filter.Filters.AddString(am.FilterBillingSubscriptionID, subID)
	orgs, err := h.orgClient.List(ctx, h.systemContext, filter)
	if err != nil {
		return nil, err
	}

	if len(orgs) != 1 {
		return nil, fmt.Errorf("organization count != 1 got ", len(orgs))
	}

	return orgs[0], nil
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
	log.Info().Str("body", string(body)).Msg("body data")
	log.Info().Str("sig", req.Header.Get("Stripe-Signature")).Msg("sig data")
	event, err := h.SigVerifier(body, req.Header.Get("Stripe-Signature"), h.endpointKey)

	if err != nil {
		log.Error().Err(err).Msg("verifying webhook signature failed")
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}

	log.Info().Msgf("incoming webhook event %#v", event)
	// Unmarshal the event data into an appropriate struct depending on its Type
	switch event.Type {
	// This is the first event for a new customer we need to handle
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
		// if customer changes their subscription level
	case "customer.subscription.updated":
		//var sub stripe.SubscriptionU
		// if customer deletes their subscription
	case "customer.subscription.deleted":
		// payment succeeded for re-occuring payments
	case "invoice.payment_succeeded":
		var invoice stripe.Invoice
		err := json.Unmarshal(event.Data.Raw, &invoice)
		if err != nil {
			log.Error().Err(err).Msg("parsing webhook JSON failed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.handleReoccurringPaymentSuccess(req.Context(), invoice)
	// payment failed for re-occuring payments
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
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func GetMetadataInt32(metadata map[string]string, key string) (int32, error) {
	var v string
	var ok bool

	if v, ok = metadata[key]; !ok {
		return 0, ErrNoMetadataKey
	}

	iv, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	return int32(iv), nil
}
