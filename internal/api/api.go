package api

import (
	"context"
	"net/http"
	"sync"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

type api struct {
	log       *zerolog.Logger
	cfg       *model.Config
	r         *gin.Engine
	srv       *http.Server
	crypto    model.CryptoService
	gui       model.GUI
	updLock   sync.Mutex
	ctx       context.Context
	ctxCancel func()
}

func New(log *zerolog.Logger, cfg *model.Config, crypto model.CryptoService, gui model.GUI) *api {
	ctx, cancel := context.WithCancel(context.Background())
	a := api{
		log:       log,
		cfg:       cfg,
		r:         gin.New(),
		crypto:    crypto,
		gui:       gui,
		ctx:       ctx,
		ctxCancel: cancel,
	}

	a.setupRoutes()
	return &a
}

func (a *api) Run(addr string) error {
	a.srv = &http.Server{
		Addr:    addr,
		Handler: a.r,
	}

	a.listenUSBEvents()

	_, _ = a.updateCertList()

	a.gui.OnFileDrop(a.SignCustomFile)

	return a.srv.ListenAndServe()
}

func (a *api) Close() {
	a.ctxCancel()
	_ = a.srv.Close()
}

func (a *api) setupRoutes() {
	a.r.Use(gin.Recovery())
	a.r.Use(corsMiddleware())

	a.r.GET("/api/certificates", a.GetCerts)
	a.r.POST("/api/fieldSign", a.SignFile)
}

// request cert list and show it in UI
func (a *api) updateCertList() ([]*model.Certificate, error) {
	a.updLock.Lock()
	defer a.updLock.Unlock()

	certs, err := a.crypto.ListHardwareCertificates()
	if err != nil {
		return nil, err
	}

	a.gui.UpdateList(certs)

	return certs, nil
}

func (a *api) abortWithError(ctx *gin.Context, code int, err error) {
	e := model.ErrorResponse{Error: err.Error()}
	ctx.AbortWithStatusJSON(code, e)
}

func corsMiddleware() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Content-Length",
			"Accept-Encoding",
			"X-CSRF-Token",
			"Authorization",
			"ResponseType",
			"accept",
			"origin",
			"Cache-Control",
			"X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	})
}
