package middleware

import "net/http"

func Health(w http.ResponseWriter, req *http.Request) {
	ReturnSuccess(w, "ok", 200)
}
