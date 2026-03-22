package model

import (
	"crypto/x509"
	"time"

	"github.com/digitorus/pdfsign/sign"
)

type CryptoService interface {
	ListHardwareCertificates() ([]*Certificate, error)
	MakeIRMSStamp(text []string, x, y float64) (*StampImage, error)
	MakeCustomStamp(text []string) (*StampImage, error)
	SignPDF(data []byte, stamp *StampImage, signInfo *SignatureInfo, cert *Certificate, password string) ([]byte, error)
}

type Certificate struct {
	SerialNumber string
	Thumbprint   string
	IssuedTo     string
	ValidTill    time.Time
	X509Cert     *x509.Certificate
	SlotId       uint
	ObjId        []byte
}

type StampImage struct {
	Image       []byte
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64
}

type SignatureInfo sign.SignDataSignatureInfo
