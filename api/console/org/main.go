package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/linkai-io/frontend/pkg/initializers"

	"github.com/apex/gateway"
	"github.com/go-chi/chi"
	"github.com/linkai-io/frontend/pkg/middleware"
	"github.com/linkai-io/frontend/pkg/serializers"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/linkai-io/am/am"
	"github.com/linkai-io/am/pkg/lb/consul"
)

var orgClient am.OrganizationService

func init() {
	zerolog.TimeFieldFormat = ""
	log.Logger = log.With().Str("lambda", "Org").Logger()
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	consul.RegisterDefault(time.Second*5, consulAddr) // Address comes from CONSUL_HTTP_ADDR or from aws metadata

	orgClient = initializers.OrgClient()
}

func GetByName(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}
	param := chi.URLParam(req, "name")
	_, org, err := orgClient.Get(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func GetByID(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	_, org, err := orgClient.GetByID(req.Context(), userContext, id)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func GetByCID(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	param := chi.URLParam(req, "cid")

	_, org, err := orgClient.GetByCID(req.Context(), userContext, param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = serializers.OrgForUsers(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func List(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	var filter am.OrgFilter

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
	}

	q := req.URL.Query()
	startStr := q.Get("start")
	if startStr != "" {
		filter.Start, err = strconv.Atoi(startStr)
		if err != nil {
			filter.Start = 0
		}
	}

	limitStr := q.Get("limit")
	if limitStr != "" {
		filter.Limit, err = strconv.Atoi(limitStr)
		if err != nil {
			filter.Limit = 10
		}
	}

	org, err := orgClient.List(req.Context(), userContext, &filter)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if data, err = json.Marshal(org); err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func Update(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte
	org := &am.Organization{}

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	if data, err = ioutil.ReadAll(req.Body); err != nil {
		log.Error().Err(err).Msg("read body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}
	defer req.Body.Close()

	if err := json.Unmarshal(data, org); err != nil {
		log.Error().Err(err).Msg("marshal body error")
		middleware.ReturnError(w, "error reading organization", 500)
		return
	}

	if _, err = orgClient.Update(req.Context(), userContext, org); err != nil {
		log.Error().Err(err).Msg("failed to update organization")
		middleware.ReturnError(w, "error updating organization", 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func Delete(w http.ResponseWriter, req *http.Request) {
	var err error
	var data []byte

	userContext, ok := middleware.ExtractUserContext(req.Context())
	if !ok {
		middleware.ReturnError(w, "missing user context", 401)
		return
	}

	param := chi.URLParam(req, "id")
	id, err := strconv.Atoi(param)
	if err != nil {
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	if _, err = orgClient.Delete(req.Context(), userContext, id); err != nil {
		log.Error().Err(err).Msg("failed to delete organization")
		middleware.ReturnError(w, err.Error(), 500)
		return
	}

	resp := make(map[string]string, 0)
	resp["status"] = "ok"

	data, _ = json.Marshal(resp)
	w.WriteHeader(200)
	fmt.Fprint(w, string(data))
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.UserCtx)

	r.Route("/org", func(r chi.Router) {
		r.Get("/name/{name}", GetByName)
		r.Get("/id/{id}", GetByID)
		r.Patch("/id/{id}", Update)
		r.Delete("/id/{id}", Delete)
		r.Get("/cid/{cid}", GetByCID)
		r.Get("/list", List)
	})

	err := gateway.ListenAndServe(":3000", r)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serve")
	}
}
