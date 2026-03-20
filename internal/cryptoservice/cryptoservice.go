package cryptoservice

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
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

// SignCustomPDF
func (c *cryptoservice) SignPDF(data []byte, stamp *model.StampImage, signInfo *model.SignatureInfo, cert *model.Certificate, password string) ([]byte, error) {
	// find signer
	signer, tokenCtx, err := c.getSigner(cert, password)
	if err != nil {
		return nil, err
	}
	defer tokenCtx.Close()

	// input data reader
	bytesReader := bytes.NewReader(data)
	pdfReader, err := pdf.NewReader(bytesReader, int64(len(data)))
	if err != nil {
		return nil, err
	}

	// output buffer
	var bytesWriter bytes.Buffer

	// force current time
	signInfo.Date = time.Now().Local()

	// sign
	err = sign.Sign(bytesReader, &bytesWriter, pdfReader, int64(len(data)), sign.SignData{
		Signature: sign.SignDataSignature{
			Info:       sign.SignDataSignatureInfo(*signInfo),
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Appearance: sign.Appearance{
			Visible:          true,
			LowerLeftX:       stamp.LowerLeftX,
			LowerLeftY:       stamp.LowerLeftY,
			UpperRightX:      stamp.UpperRightX,
			UpperRightY:      stamp.UpperRightY,
			Image:            stamp.Image,
			ImageAsWatermark: false, // draw text over image
		},
		Signer:          signer,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     cert.X509Cert,
	})
	if err != nil {
		return nil, err
	}

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

func (c *cryptoservice) MakeIRMSStamp(text []string, x, y float64) (*model.StampImage, error) {
	signatureImage, err := gg.LoadImage(c.cfg.StampBg)
	if err != nil {
		return nil, err
	}
	dc := gg.NewContextForImage(signatureImage)
	return c.makeStamp(dc, text, x, y, 85, 62, 18, 14)
}

func (c *cryptoservice) MakeCustomStamp(text []string, x, y, w, h, lineStep, fontSize float64) (*model.StampImage, error) {
	dc := gg.NewContext(int(w), int(h))
	dc.SetRGB(0.8, 1, 0.8)
	dc.DrawRoundedRectangle(1, 1, w-2, h-2, 15)
	dc.Fill()
	return c.makeStamp(dc, text, x, y, 10, 10, lineStep, fontSize)
}

func (c *cryptoservice) makeStamp(dc *gg.Context, text []string, x, y, textX, textY, lineStep, fontSize float64) (*model.StampImage, error) {
	dc.SetRGB(0, 0, 0)

	if err := dc.LoadFontFace(c.cfg.Font, float64(fontSize)); err != nil {
		return nil, err
	}

	for _, s := range text {
		dc.DrawStringAnchored(s, textX, textY, 0, 1)
		textY += lineStep
	}

	var imgWriter bytes.Buffer
	err := dc.EncodePNG(&imgWriter)
	if err != nil {
		return nil, err
	}

	stamp := model.StampImage{
		Image:       imgWriter.Bytes(),
		LowerLeftX:  x,
		LowerLeftY:  y,
		UpperRightX: x + float64(dc.Width())/2,
		UpperRightY: y + float64(dc.Height())/2,
	}
	return &stamp, nil
}
