package model

import (
	"crypto/x509"
	"time"
)

type CryptoService interface {
	ListHardwareCertificates() ([]*Certificate, error)
	SignPDF(req *FieldSignRequest, cert *Certificate, password string) ([]byte, error)
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
