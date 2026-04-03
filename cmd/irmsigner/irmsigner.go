package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"

	"github.com/mannulus-immortalis/irmsigner/internal/api"
	"github.com/mannulus-immortalis/irmsigner/internal/config"
	"github.com/mannulus-immortalis/irmsigner/internal/cryptoservice"
	"github.com/mannulus-immortalis/irmsigner/internal/gui"
	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

func main() {
	var err error
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	log.Info().Str("Version", model.Version).Msg("IRMSigner is starting")

	cfg, err := config.LoadConfig("config.yml")
	if err != nil {
		log.Err(err).Msg("Config load failed")
		return
	}

	// Crypto
	crypto, err := cryptoservice.New(cfg)
	if err != nil {
		log.Err(err).Msg("Crypto init failed")
		return
	}

	// GUI
	guiStopChan := make(chan bool)
	gui, err := gui.New(&log, cfg, guiStopChan)
	if err != nil {
		log.Err(err).Msg("GUI init failed")
		return
	}

	// setup API
	api := api.New(&log, cfg, crypto, gui)

	// run server in background
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- api.Run(cfg.Listen)
	}()

	log.Info().Str("Port", cfg.Listen).Msg("Listening...")

	// listen to OS signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-guiStopChan:
		log.Info().Msg("gui closed")
		api.Close()
	case err = <-serverErrors:
		log.Err(err).Msg("received server error")
		gui.Stop()
	case <-sig:
		log.Info().Msg("received shutdown signal")
		gui.Stop()
		api.Close()
	}

}
