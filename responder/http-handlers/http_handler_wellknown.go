package http_handlers

import (
	"github.com/sirupsen/logrus"
	"net/http"
	"github.com/tenta-browser/tenta-dns/runtime"
	"fmt"
)

func HandleHTTPWellKnown(cfg runtime.NSnitchConfig, rt *runtime.Runtime, lgr *logrus.Entry, path string, body []byte, mime string) httpHandler {
	bodylen := fmt.Sprintf("%d", len(body))
	return wrapExtendedHttpHandler(rt, lgr, "well-known", func(w http.ResponseWriter, r *http.Request, lg *logrus.Entry) {
		lgr.Debugf("Serving well-known %s", path)
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Length", bodylen)
		extraHeaders(cfg, w, r)
		w.WriteHeader(200)
		w.Write(body)
	})
}
