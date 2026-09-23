package app

import (
	"fmt"
	"time"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

// CryptoPort defines the dependency boundary for the application layer.
// It intentionally mirrors the existing crypto capabilities without depending
// on GTK or HTTP transport details.
type CryptoPort interface {
	ListHardwareCertificates() ([]*model.Certificate, error)
	GetDefaultStampPos() (x, y float64)
	MakeCustomStamp(text []string, x, y float64) (*model.StampImage, error)
	SignPDF(data []byte, stamp *model.StampImage, signInfo *model.SignatureInfo, cert *model.Certificate, password string) ([]byte, error)
}

// GUIAdapter abstracts the UI layer so the app logic can remain testable.
type GUIAdapter interface {
	UpdateList(list []*model.Certificate)
	RequestPass(certTitle string) string
	OnFileDrop(f model.FileDropFunc)
	StartSpinner() (func(), error)
	ShowMessage(text, status string) error
	Stop()
	Run()
}

// UseCase is the application layer that owns the high-level workflow while
// keeping transport and hardware logic behind interfaces.
type UseCase struct {
	cfg    *model.Config
	crypto CryptoPort
	gui    GUIAdapter
}

func New(cfg *model.Config, crypto CryptoPort, gui GUIAdapter) *UseCase {
	return &UseCase{cfg: cfg, crypto: crypto, gui: gui}
}

func (u *UseCase) ListCertificates() ([]*model.Certificate, error) {
	if u.crypto == nil {
		return nil, fmt.Errorf("crypto service is nil")
	}
	return u.crypto.ListHardwareCertificates()
}

func (u *UseCase) BuildStamp(text []string) (*model.StampImage, error) {
	if u.crypto == nil {
		return nil, fmt.Errorf("crypto service is nil")
	}
	if len(text) == 0 {
		text = []string{"Digitally signed by"}
	}

	x, y := u.crypto.GetDefaultStampPos()
	return u.crypto.MakeCustomStamp(text, x, y)
}

func (u *UseCase) SignDocument(data []byte, cert *model.Certificate, password string, text []string) ([]byte, error) {
	if u.crypto == nil {
		return nil, fmt.Errorf("crypto service is nil")
	}
	if cert == nil {
		return nil, model.ErrCertNotFound
	}
	if len(text) == 0 {
		text = []string{
			"Digitally signed by",
			cert.IssuedTo,
			time.Now().Format("2006-01-02 15:04:05Z07:00"),
		}
	}

	stamp, err := u.BuildStamp(text)
	if err != nil {
		return nil, err
	}

	signInfo := &model.SignatureInfo{Name: cert.IssuedTo}
	return u.crypto.SignPDF(data, stamp, signInfo, cert, password)
}
