package webhook

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/nlopes/slack"

	"github.com/linkai-io/am/am"
)

func FormatSlackMessage(groupName string, e *am.Event) (string, error) {
	headerText := slack.NewTextBlockObject("mrkdwn", ":information_source: Hakken Alert for :"+groupName, true, false)
	headerSection := slack.NewSectionBlock(headerText, nil, nil)

	var alertSection *slack.SectionBlock

	switch e.TypeID {
	case am.EventCertExpiredID:
	case am.EventCertExpiringID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following certificates will expire soon:", true, false)

		if e.JSONData != "" && e.JSONData != "{}" {
			// handle new json type
			var expireCerts []*am.EventCertExpiring
			if err := json.Unmarshal([]byte(e.JSONData), &expireCerts); err != nil {
				return "", err
			}
			alertFields := make([]*slack.TextBlockObject, len(expireCerts))
			for i, expired := range expireCerts {
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("%s on port %d expires in %s\n", expired.SubjectName, expired.Port, FormatUnixTimeRemaining(expired.ValidTo)), true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}

	case am.EventNewOpenPortID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following ports were opened:", true, false)
		if e.JSONData != "" && e.JSONData != "{}" {
			var openPorts []*am.EventNewOpenPort
			if err := json.Unmarshal([]byte(e.JSONData), &openPorts); err != nil {
				return "", err
			}

			alertFields := make([]*slack.TextBlockObject, len(openPorts))
			for i, open := range openPorts {
				ips := open.CurrentIP
				if open.CurrentIP != open.PreviousIP {
					ips += ") previously (" + open.PreviousIP
				}
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Host %s (%s) ports: %s\n", open.Host, ips, IntToString(open.OpenPorts)), true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}
	case am.EventClosedPortID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following ports were recently closed:", true, false)
		if e.JSONData != "" && e.JSONData != "{}" {
			var closedPorts []*am.EventClosedPort
			if err := json.Unmarshal([]byte(e.JSONData), &closedPorts); err != nil {
				return "", err
			}

			alertFields := make([]*slack.TextBlockObject, len(closedPorts))
			for i, closed := range closedPorts {
				ips := closed.CurrentIP
				if closed.CurrentIP != closed.PreviousIP {
					ips += ") previously (" + closed.PreviousIP
				}
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Host %s (%s) ports: %s\n", closed.Host, ips, IntToString(closed.ClosedPorts)), true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}
	case am.EventInitialGroupCompleteID:
	case am.EventMaxHostPricingID:
	case am.EventNewHostID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following new hosts were found:", true, false)

		if e.JSONData != "" && e.JSONData != "{}" {
			var newHosts []*am.EventNewHost
			if err := json.Unmarshal([]byte(e.JSONData), &newHosts); err != nil {
				return "", err
			}
			alertFields := make([]*slack.TextBlockObject, len(newHosts))
			for i, newHost := range newHosts {
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", newHost.Host, true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}

	case am.EventAXFRID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following name servers allow Zone Transfers (AXFR):", true, false)
		if e.JSONData != "" && e.JSONData != "{}" {
			var axfrServers []*am.EventAXFR
			if err := json.Unmarshal([]byte(e.JSONData), &axfrServers); err != nil {
				return "", err
			}
			alertFields := make([]*slack.TextBlockObject, len(axfrServers))
			for i, axfr := range axfrServers {
				log.Printf("%#v %s", axfr, strings.Join(axfr.Servers, ","))
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", strings.Join(axfr.Servers, ","), true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}
	case am.EventNSECID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following name servers are leaking hostnames via NSEC records:", true, false)

		if e.JSONData != "" && e.JSONData != "{}" {
			var nsecServers []*am.EventNSEC
			if err := json.Unmarshal([]byte(e.JSONData), &nsecServers); err != nil {
				return "", err
			}
			alertFields := make([]*slack.TextBlockObject, len(nsecServers))
			for i, nsec := range nsecServers {
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", strings.Join(nsec.Servers, ","), true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}

	case am.EventNewWebsiteID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following new web sites were found:", true, false)

		if e.JSONData != "" && e.JSONData != "{}" {
			var newSites []*am.EventNewWebsite
			if err := json.Unmarshal([]byte(e.JSONData), &newSites); err != nil {
				return "", err
			}

			alertFields := make([]*slack.TextBlockObject, len(newSites))
			for i, site := range newSites {
				msg := ""
				if wasRedirected(site.LoadURL, site.URL) {
					msg = fmt.Sprintf("%s (was redirected to %s) on port %d", site.LoadURL, site.URL, site.Port)
				} else {
					msg = fmt.Sprintf("%s on port %d", site.LoadURL, site.Port)
				}
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", msg, true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}
	case am.EventWebHTMLUpdatedID:
	case am.EventWebJSChangedID:
	case am.EventNewWebTechID:
		alertHeaderText := slack.NewTextBlockObject("mrkdwn", "The following new or updated technologies were found:", true, false)

		if e.JSONData != "" && e.JSONData != "{}" {
			var newTech []*am.EventNewWebTech
			if err := json.Unmarshal([]byte(e.JSONData), &newTech); err != nil {
				return "", err
			}

			alertFields := make([]*slack.TextBlockObject, len(newTech))
			for i, tech := range newTech {
				msg := ""
				if wasRedirected(tech.LoadURL, tech.URL) {
					msg = fmt.Sprintf("%s (was redirected to %s) is running %s %s", tech.LoadURL, tech.URL, tech.TechName, tech.Version)
				} else {
					msg = fmt.Sprintf("%s is running %s %s", tech.LoadURL, tech.TechName, tech.Version)
				}
				alertFields[i] = slack.NewTextBlockObject("mrkdwn", msg, true, false)
			}
			alertSection = slack.NewSectionBlock(alertHeaderText, alertFields, nil)
		}
	}
	block := slack.NewBlockMessage(headerSection,
		alertSection)

	type attach struct {
		Color  string       `json:"color"`
		Blocks slack.Blocks `json:"blocks"`
	}

	type stupidSDK struct {
		Text        string   `json:"text"`
		Blocks      []string `json:"blocks"`
		Attachments *attach  `json:"attachments"`
	}
	v := &stupidSDK{
		Text:        "what",
		Attachments: &attach{Color: "#f3c", Blocks: block.Blocks},
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	log.Printf("%s\n", string(data))
	return string(data), nil
}
