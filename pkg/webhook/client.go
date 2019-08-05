package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/parsers"
)

type WebhookEvent struct {
	URL       string    `json:"url"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	ScanGroup string    `json:"scan_group"`
	Event     *am.Event `json:"event"`
}

type WebhookEventResponse struct {
	StatusCode    int    `json:"status_code"`
	DeliveredTime int64  `json:"delivery_time"`
	Error         string `json:"error"`
}

type Client struct {
	c *http.Client
}

func New() *Client {
	timeout := 10 * time.Second
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if parsers.IsBannedIP(ip) {
				log.Printf("BANNED IP")
				return nil, errors.New("ip address is banned")
			}
			return c, err
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			c, err := tls.Dial(network, addr, &tls.Config{})
			if err != nil {
				return nil, err
			}

			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if parsers.IsBannedIP(ip) {
				log.Printf("TLS BANNED IP")
				return nil, errors.New("ip address is banned")
			}

			err = c.Handshake()
			if err != nil {
				return c, err
			}

			return c, c.Handshake()
		},
		TLSHandshakeTimeout: 9 * time.Second,
	}

	return &Client{c: &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   timeout,
	}}
}

func (c *Client) SendEvent(evt *WebhookEvent) (int, error) {
	switch evt.Type {
	case "slack":
		return c.sendSlackEvent(evt)
	case "custom":
		return c.sendCustomEvent(evt)
	case "custom_signed":
		return c.sendCustomSignedEvent(evt)
	}
	return 0, errors.New("invalid webhook type")
}

func (c *Client) sendSlackEvent(evt *WebhookEvent) (int, error) {
	msg, err := FormatSlackMessage(evt.ScanGroup, evt.Event)
	if err != nil {
		return 0, err
	}
	resp, err := c.c.Post(evt.URL, "application/json", strings.NewReader(msg))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func (c *Client) sendCustomEvent(evt *WebhookEvent) (int, error) {
	return 0, nil
}

func (c *Client) sendCustomSignedEvent(evt *WebhookEvent) (int, error) {
	return 0, nil
}
