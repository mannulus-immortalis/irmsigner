package model

import (
	"errors"
)

const (
	Version = "v0.1.0"
)

var (
	ErrNotFound         = errors.New("Item not found")
	ErrConfigNotFound   = errors.New("Config not found")
	ErrInvalidRequest   = errors.New("Invalid request")
	ErrCertNotFound     = errors.New("Certificate not found")
	ErrAccessDenied     = errors.New("Access denied")
	ErrPasswordRequired = errors.New("Password Required")
	ErrColumns          = errors.New("Columns")
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type CertificatesResponse []CertificateItem
type CertificateItem struct {
	SerialNumber               string  `json:"SerialNumber"`               // MANUALLY ADDED, does not exist in original response
	Id                         int     `json:"Id"`                         // 0
	IssuedTo                   string  `json:"IssuedTo"`                   // "FirstName LastName"
	IssuedBy                   string  `json:"IssuedBy"`                   // "PostaCG CA"
	NotBefore                  string  `json:"NotBefore"`                  // "11/07/2024"
	NotAfter                   string  `json:"NotAfter"`                   // "11/07/2027"
	IdStatusa                  int     `json:"IdStatusa"`                  // 666
	BrojStatusa                string  `json:"BrojStatusa"`                // "OKToSign"
	Thumbprint                 string  `json:"Thumbprint"`                 // 20-digit hex SHA-1 of cert body
	OID                        string  `json:"OID"`                        // "OID = 1.3.6.1.4.1.36737.1.1.1.1"
	Cert                       *string `json:"Cert"`                       // TODO unknown type, null in example
	StatusSertifikata          *string `json:"statusSertifikata"`          // TODO unknown type, null in example
	KvalifikovanostSertifikata string  `json:"KvalifikovanostSertifikata"` // "Ovo je kvalifikovani sertifikat za elektronske potpise u skladu sa propisima Evropske unije.\r\nSertifikat i privatni kriptografski ključ su smešteni u sredstvu za formiranje kvalifikovanog elektronskog potpisa\r\n\r\n"
	CertificatePolicyLocation  *string `json:"CertificatePolicyLocation"`  // TODO unknown type, null in example
	StatusSert                 *string `json:"statusSert"`                 // TODO unknown type, null in example
	OpisGreske                 string  `json:"OpisGreske"`                 // ""
	OpisStatusa                string  `json:"OpisStatusa"`                // "Sertifikat je OK. Provera opoziva sertifikata će biti obavljena prilikom potpisivanja."
	SertifikatSaStat           struct {
		Cert                      *string `json:"cert"`                      // TODO unknown type, null in example
		Root                      *string `json:"Root"`                      // TODO unknown type, null in example
		CertificatePolicyOID      *string `json:"CertificatePolicyOID"`      // TODO unknown type, null in example
		CertificatePolicyLocation *string `json:"CertificatePolicyLocation"` // TODO unknown type, null in example
		UserNotice                *string `json:"UserNotice"`                // TODO unknown type, null in example
		QC                        *string `json:"QC"`                        // TODO unknown type, null in example
		StatusSertifikata         *string `json:"StatusSertifikata"`         // TODO unknown type, null in example
	} `json:"SertifikatSaStat"`
}

type FieldSignRequest struct {
	SigningFileStream            string  `json:"SigningFileStream"`            // "base64encodedstring"
	SigningCertificateThumbprint string  `json:"SigningCertificateThumbprint"` // 20-digit hex SHA-1 of cert body
	Location                     *string `json:"Location"`                     // TODO unknown type, null in example
	ContactInfo                  *string `json:"ContactInfo"`                  // TODO unknown type, null in example
	Reason                       string  `json:"Reason"`                       // "Dokument"
	FieldImage                   *string `json:"FieldImage"`                   // TODO unknown type, null in example
	TimeServers                  string  `json:"TimeServers"`                  // "time.google.com"
	IsPdfSignatureVisual         bool    `json:"IsPdfSignatureVisual"`         // true
	IncludeTimestamp             bool    `json:"IncludeTimestamp"`             // false
	TimeStampServers             string  `json:"TimeStampServers"`             // "http://timestamp.digicert.com"
	DocumentClassId              int     `json:"DocumentClassId"`              // 0
	DocumentId                   int     `json:"DocumentId"`                   // 0
	MultiSign                    bool    `json:"MultiSign"`                    // false
	Note                         *string `json:"Note"`                         // TODO unknown type, null in example
	YCoordinate                  int     `json:"YCoordinate"`                  // 5
	XCoordinate                  int     `json:"XCoordinate"`                  // 390
}

type FieldSignResponse struct {
	SignedFileStream *string `json:"SignedFileStream"` // base64-encoded string
	SignedXmlContent *string `json:"SignedXmlContent"` // null in example
}
