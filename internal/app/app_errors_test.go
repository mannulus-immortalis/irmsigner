package app

import (
	"errors"
	"testing"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

func TestUseCasePropagatesStampError(t *testing.T) {
	wantErr := errors.New("font unavailable")
	uc := New(nil, &cryptoMock{stampErr: wantErr}, nil)

	_, err := uc.BuildStamp([]string{"signed"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("BuildStamp() error = %v, want %v", err, wantErr)
	}
}

func TestUseCasePropagatesSigningError(t *testing.T) {
	wantErr := errors.New("signing failed")
	cert := &model.Certificate{IssuedTo: "Alice"}
	crypto := &cryptoMock{stamp: &model.StampImage{}, signErr: wantErr}
	uc := New(nil, crypto, nil)

	_, err := uc.SignDocument([]byte("pdf"), cert, "1234", []string{"custom"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("SignDocument() error = %v, want %v", err, wantErr)
	}
}
