package config

import (
	"os"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

func LoadConfig(filename string) (*model.Config, error) {
	l := log.With().Str("File", filename).Logger()
	var cfg model.Config
	data, err := os.ReadFile(filename)
	if err != nil {
		l.Err(err).Msg("Config not found, using default values")
	} else {
		err = yaml.Unmarshal(data, &cfg)
		if err != nil {
			l.Err(err).Msg("Invalid config")
			return nil, err
		}
	}
	// default values
	if cfg.Listen == "" {
		cfg.Listen = ":8984"
	}
	if cfg.Pkcs11Lib == "" {
		cfg.Pkcs11Lib = "/usr/lib/opensc-pkcs11.so"
	}
	if cfg.StampBg == "" {
		cfg.StampBg = "./img/stamp_bg.png"
	}
	if cfg.Font == "" {
		cfg.Font = "./img/LiberationSans-Regular.ttf"
	}

	return &cfg, nil
}
