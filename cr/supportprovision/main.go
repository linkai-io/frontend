package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/rs/zerolog/log"
)

// pretend to provision data...
func provisionResource(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	evtData, _ := json.Marshal(event)
	log.Info().Msgf("event data: %s", string(evtData))
	log.Info().Msgf("run for cleanup: curl -H 'Content-Type:' -H 'Content-Length: 0' -X PUT \"%s\"", event.ResponseURL)
	data := make(map[string]interface{}, 0)
	data["some_response"] = "data"
	return "some_id", data, nil
}

func main() {
	fn := func(ctx context.Context, event cfn.Event) (reason string, err error) {
		r := cfn.NewResponse(&event)

		r.PhysicalResourceID, r.Data, err = provisionResource(ctx, event)
		if r.PhysicalResourceID == "" {
			r.PhysicalResourceID = lambdacontext.LogStreamName
		}

		if err != nil {
			r.Status = cfn.StatusFailed
			r.Reason = err.Error()
			log.Error().Err(err).Str("reason", r.Reason).Msg("sending status failed")
		} else {
			r.Status = cfn.StatusSuccess
		}

		err = r.Send()
		if err != nil {
			reason = err.Error()
			log.Error().Err(err).Str("reason", r.Reason).Msg("sending failed, falling back to failsafe")
			return "", failSafe(r, event)
		}
		return
	}
	lambda.Start(fn)
}

func failSafe(r *cfn.Response, event cfn.Event) error {
	client := http.DefaultClient
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, event.ResponseURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	log.Info().Str("url", event.ResponseURL).Str("body", string(body)).Msg("calling url")
	req.Header.Del("Content-Type")
	req.Header.Set("Content-Length", string(int64(len(body))))

	res, err := client.Do(req)
	if err != nil {
		return err
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	res.Body.Close()

	if res.StatusCode != 200 {
		log.Error().Str("response_body", string(body)).Int("code", res.StatusCode).Msg("failed again")
		return errors.New("invalid status code")
	}

	return nil
}
