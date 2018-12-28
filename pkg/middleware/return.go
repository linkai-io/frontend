package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

type WebResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func ReturnError(w http.ResponseWriter, msg string, code int) {
	resp := &WebResponse{Status: "error", Msg: msg}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to returnError due to marshal failure")
		w.WriteHeader(500)
		fmt.Fprint(w, "{\"status\":\"error\"}")
		return
	}
	w.WriteHeader(code)
	fmt.Fprint(w, string(data))
}

func ReturnSuccess(w http.ResponseWriter, msg string, code int) {
	resp := &WebResponse{Status: "OK", Msg: msg}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to return success due to marshal failure")
		w.WriteHeader(500)
		fmt.Fprint(w, "{\"status\":\"error\"}")
		return
	}
	w.WriteHeader(code)
	fmt.Fprint(w, string(data))
}
