package model

type Config struct {
	Listen    string `yaml:"listen"`
	Pkcs11Lib string `yaml:"pkcs11_lib"`
	StampBg   string `yaml:"stamp_background"`
	Font      string `yaml:"font"`
	FontSize  int    `yaml:"font_size"`
}
