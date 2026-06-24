package config

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

// assetPath resolves a relative asset path against the binary's own directory
// so the app finds its assets regardless of the working directory.
func assetPath(rel string) string {
	exe, err := os.Executable()
	if err != nil {
		return rel
	}
	return filepath.Join(filepath.Dir(exe), rel)
}

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
		cfg.Pkcs11Lib = defaultPkcs11Lib
	}
	if cfg.StampBg == "" {
		cfg.StampBg = assetPath("img/stamp_bg.png")
	}
	if cfg.Font == "" {
		cfg.Font = assetPath("img/LiberationSans-Regular.ttf")
	}

	return &cfg, nil
}
