package webdata

import (
	"github.com/linkai-io/am/am"
	"github.com/linkai-io/frontend/pkg/middleware"
)

type WebHandlers struct {
	webClient        am.WebDataService
	scanGroupClient  am.ScanGroupService
	ContextExtractor middleware.UserContextExtractor
}

func New(webClient am.WebDataService, scanGroupClient am.ScanGroupService) *WebHandlers {
	return &WebHandlers{
		webClient:        webClient,
		scanGroupClient:  scanGroupClient,
		ContextExtractor: middleware.ExtractUserContext,
	}
}
