package cryptoservice

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	"github.com/fogleman/gg"
	"github.com/miekg/pkcs11"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

const (
	KeyUsageContentCommitment = 1
)

type cryptoservice struct {
	cfg *model.Config
}

func New(cfg *model.Config) (*cryptoservice, error) {
	return &cryptoservice{cfg: cfg}, nil
}

// ListHardwareCertificates lists all available certificates
func (c *cryptoservice) ListHardwareCertificates() ([]*model.Certificate, error) {
	p := pkcs11.New(c.cfg.Pkcs11Lib)
	err := p.Initialize()
	if err != nil {
		return nil, err
	}
	defer func() {
		p.Finalize()
		p.Destroy()
	}()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	certList := make([]*model.Certificate, 0)

	for _, slotId := range slots {
		session, err := p.OpenSession(slotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, err
		}

		err = p.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		})
		if err != nil {
			return nil, err
		}

		objects, _, err := p.FindObjects(session, 20)
		if err != nil {
			return nil, err
		}
		if objects == nil {
			break
		}

		for _, object := range objects {
			attrs, err := p.GetAttributeValue(session, object, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, nil),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			})
			if err != nil {
				continue
			}

			isCC := false
			cert := model.Certificate{
				SlotId: slotId,
			}
			for i := range attrs {
				switch attrs[i].Type {
				case pkcs11.CKA_ID:
					cert.ObjId = attrs[i].Value
				case pkcs11.CKA_SERIAL_NUMBER:
					cert.SerialNumber = fmt.Sprintf("%X", attrs[i].Value)
				case pkcs11.CKA_VALUE:
					certInfo, err := x509.ParseCertificate(attrs[i].Value)
					if err != nil {
						return nil, err
					}

					keyUsage := int(certInfo.KeyUsage)
					ccMask := 1 << KeyUsageContentCommitment
					isCC = keyUsage&ccMask > 0

					cert.X509Cert = certInfo
					cert.Thumbprint = fmt.Sprintf("%X", sha1.Sum(attrs[i].Value))
					cert.IssuedTo = certInfo.Subject.CommonName
					cert.ValidTill = certInfo.NotAfter
				}
			}
			if isCC { // list only CC certificates
				certList = append(certList, &cert)
			}
		}
		err = p.FindObjectsFinal(session)
		if err != nil {
			return nil, err
		}
		p.CloseSession(session)
	}
	return certList, nil
}

// SignPDF signs requested pdf with given certificate and password
func (c *cryptoservice) SignPDF(req *model.FieldSignRequest, cert *model.Certificate, password string) ([]byte, error) {
	// find signer
	signer, tokenCtx, err := c.getSigner(cert, password)
	if err != nil {
		return nil, err
	}
	defer tokenCtx.Close()

	// prepare input data
	data, err := base64.StdEncoding.DecodeString(req.SigningFileStream)
	if err != nil {
		return nil, err
	}
	req.SigningFileStream = "" // free mem

	bytesReader := bytes.NewReader(data)
	pdfReader, err := pdf.NewReader(bytesReader, int64(len(data)))
	if err != nil {
		return nil, err
	}

	// output buffer
	var bytesWriter bytes.Buffer

	// prepare stamp image
	stampImg, err := c.makeStampImage([]string{
		cert.SerialNumber[len(cert.SerialNumber)-8:],
		time.Now().Format("02.01.2006 15:04:05"),
	})
	if err != nil {
		return nil, err
	}

	// fill signature info
	info := sign.SignDataSignatureInfo{
		Date: time.Now().Local(),
	}
	if req.Location != nil {
		info.Location = *req.Location
	}
	if req.ContactInfo != nil {
		info.ContactInfo = *req.ContactInfo
	}
	if req.Reason != "" {
		info.Reason = req.Reason
	}

	// sign
	err = sign.Sign(bytesReader, &bytesWriter, pdfReader, int64(len(data)), sign.SignData{
		Signature: sign.SignDataSignature{
			Info:       info,
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
			Visible:          true,
			LowerLeftX:       float64(req.XCoordinate),
			LowerLeftY:       float64(req.YCoordinate),
			UpperRightX:      float64(req.XCoordinate + 150),
			UpperRightY:      float64(req.YCoordinate + 50),
			Image:            stampImg,
			ImageAsWatermark: false, // draw text over image
		},
		Signer:          signer,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     cert.X509Cert,
	})
	if err != nil {
		return nil, err
	}

	// save local copy of signed document
	outputFile, err := os.Create(fmt.Sprintf("signed-%s.pdf", time.Now().Format("2006-01-02-150405")))
	if err != nil {
		return nil, err
	}
	outputFile.Write(bytesWriter.Bytes())
	outputFile.Close()

	return bytesWriter.Bytes(), nil
}

// getSigner prepares hardware signer. Call tokenCtx.Close() when done
func (c *cryptoservice) getSigner(cert *model.Certificate, password string) (crypto11.SignerDecrypter, *crypto11.Context, error) {
	if password == "" {
		return nil, nil, model.ErrPasswordRequired
	}

	// prepare hardware signer
	slotId := int(cert.SlotId)
	tokenCtx, err := crypto11.Configure(&crypto11.Config{
		Path:       c.cfg.Pkcs11Lib,
		SlotNumber: &slotId,
		Pin:        password,
	})
	if err != nil {
		return nil, nil, err
	}

	signer, err := tokenCtx.FindRSAKeyPair(cert.ObjId, nil)
	if err != nil {
		tokenCtx.Close()
		return nil, nil, err
	}

	if signer == nil {
		tokenCtx.Close()
		return nil, nil, model.ErrNotFound
	}
	return signer, tokenCtx, err
}

func (c *cryptoservice) makeStampImage(text []string) ([]byte, error) {
	signatureImage, err := gg.LoadImage(c.cfg.StampBg)
	if err != nil {
		return nil, err
	}

	dc := gg.NewContextForImage(signatureImage)
	dc.SetRGB(0, 0, 0)

	if err := dc.LoadFontFace(c.cfg.Font, float64(c.cfg.FontSize)); err != nil {
		return nil, err
	}

	x := 85.0
	y := 75.0

	for i, s := range text {
		lineY := y + float64(i*18)
		dc.DrawStringAnchored(s, x, lineY, 0, 0)
	}

	var imgWriter bytes.Buffer
	err = dc.EncodePNG(&imgWriter)
	if err != nil {
		return nil, err
	}
	return imgWriter.Bytes(), nil
}
