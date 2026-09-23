package app

import (
	"errors"
	"testing"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

type cryptoMock struct {
	certs       []*model.Certificate
	stamp       *model.StampImage
	stampText   []string
	signed      []byte
	signInfo    *model.SignatureInfo
	signCert    *model.Certificate
	signPass    string
	listCalls   int
	stampCalls  int
	signCalls   int
	listErr     error
	stampErr    error
	signErr     error
}

func (m *cryptoMock) ListHardwareCertificates() ([]*model.Certificate, error) {
	m.listCalls++
	return m.certs, m.listErr
}

func (m *cryptoMock) GetDefaultStampPos() (float64, float64) { return 10, 20 }

func (m *cryptoMock) MakeCustomStamp(text []string, x, y float64) (*model.StampImage, error) {
	m.stampCalls++
	m.stampText = append([]string(nil), text...)
	if m.stampErr != nil {
		return nil, m.stampErr
	}
	if m.stamp == nil {
		m.stamp = &model.StampImage{LowerLeftX: x, LowerLeftY: y}
	}
	return m.stamp, nil
}

func (m *cryptoMock) SignPDF(data []byte, stamp *model.StampImage, info *model.SignatureInfo, cert *model.Certificate, password string) ([]byte, error) {
	m.signCalls++
	m.signInfo = info
	m.signCert = cert
	m.signPass = password
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.signed, nil
}

func TestUseCaseListCertificates(t *testing.T) {
	want := []*model.Certificate{{SerialNumber: "123"}}
	crypto := &cryptoMock{certs: want}
	uc := New(nil, crypto, nil)

	got, err := uc.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("ListCertificates() = %#v, want %#v", got, want)
	}
	if crypto.listCalls != 1 {
		t.Fatalf("ListHardwareCertificates calls = %d, want 1", crypto.listCalls)
	}
}

func TestUseCaseListCertificatesPropagatesError(t *testing.T) {
	wantErr := errors.New("token unavailable")
	uc := New(nil, &cryptoMock{listErr: wantErr}, nil)

	_, err := uc.ListCertificates()
	if !errors.Is(err, wantErr) {
		t.Fatalf("ListCertificates() error = %v, want %v", err, wantErr)
	}
}

func TestUseCaseBuildStampUsesDefaultPosition(t *testing.T) {
	crypto := &cryptoMock{stamp: &model.StampImage{Image: []byte("stamp")}}
	uc := New(nil, crypto, nil)

	got, err := uc.BuildStamp([]string{"signed"})
	if err != nil {
		t.Fatalf("BuildStamp() error = %v", err)
	}
	if got != crypto.stamp {
		t.Fatalf("BuildStamp() returned unexpected stamp")
	}
	if crypto.stampCalls != 1 || len(crypto.stampText) != 1 || crypto.stampText[0] != "signed" {
		t.Fatalf("unexpected stamp call: calls=%d text=%v", crypto.stampCalls, crypto.stampText)
	}
}

func TestUseCaseBuildStampProvidesDefaultText(t *testing.T) {
	crypto := &cryptoMock{stamp: &model.StampImage{}}
	uc := New(nil, crypto, nil)

	if _, err := uc.BuildStamp(nil); err != nil {
		t.Fatalf("BuildStamp() error = %v", err)
	}
	if len(crypto.stampText) != 1 || crypto.stampText[0] != "Digitally signed by" {
		t.Fatalf("default stamp text = %v", crypto.stampText)
	}
}

func TestUseCaseSignDocument(t *testing.T) {
	cert := &model.Certificate{IssuedTo: "Alice"}
	crypto := &cryptoMock{stamp: &model.StampImage{}, signed: []byte("signed pdf")}
	uc := New(nil, crypto, nil)

	got, err := uc.SignDocument([]byte("pdf"), cert, "1234", []string{"custom"})
	if err != nil {
		t.Fatalf("SignDocument() error = %v", err)
	}
	if string(got) != "signed pdf" {
		t.Fatalf("SignDocument() = %q, want %q", got, "signed pdf")
	}
	if crypto.signCert != cert || crypto.signPass != "1234" {
		t.Fatalf("sign arguments were not forwarded")
	}
	if crypto.signInfo == nil || crypto.signInfo.Name != "Alice" {
		t.Fatalf("sign info = %#v", crypto.signInfo)
	}
}

func TestUseCaseSignDocumentRequiresCertificate(t *testing.T) {
	uc := New(nil, &cryptoMock{}, nil)

	_, err := uc.SignDocument([]byte("pdf"), nil, "1234", nil)
	if !errors.Is(err, model.ErrCertNotFound) {
		t.Fatalf("SignDocument() error = %v, want %v", err, model.ErrCertNotFound)
	}
}
