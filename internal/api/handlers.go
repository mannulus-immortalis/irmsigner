package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

func (a *api) GetCerts(ctx *gin.Context) {
	certs, err := a.updateCertList()
	if err != nil {
		a.log.Err(err).Msg("ListHardwareCertificates failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}

	resp := make(model.CertificatesResponse, 0, len(certs))
	for _, c := range certs {
		resp = append(resp, model.CertificateItem{
			SerialNumber:               c.SerialNumber,
			Id:                         len(resp),
			IssuedTo:                   c.X509Cert.Subject.CommonName,
			IssuedBy:                   c.X509Cert.Issuer.CommonName,
			NotBefore:                  c.X509Cert.NotBefore.Format("02/01/2006"),
			NotAfter:                   c.X509Cert.NotAfter.Format("02/01/2006"),
			IdStatusa:                  666,
			BrojStatusa:                "OKToSign",
			Thumbprint:                 c.Thumbprint,
			OID:                        "OID = " + c.X509Cert.PolicyIdentifiers[0].String(),
			KvalifikovanostSertifikata: "Ovo je kvalifikovani sertifikat za elektronske potpise u skladu sa propisima Evropske unije.\r\nSertifikat i privatni kriptografski ključ su smešteni u sredstvu za formiranje kvalifikovanog elektronskog potpisa\r\n\r\n",
			OpisStatusa:                "Sertifikat je OK. Provera opoziva sertifikata će biti obavljena prilikom potpisivanja.",
		})
	}

	ctx.JSON(http.StatusOK, resp)
}

func (a *api) SignFile(ctx *gin.Context) {
	if a.cfg.LogRequests {
		body, _ := io.ReadAll(ctx.Request.Body)
		ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
		reqFileName := fmt.Sprintf("irms-request-%s.json", time.Now().Format("2006-01-02-150405"))
		reqFile, err := os.Create(reqFileName)
		if err == nil {
			reqFile.Write(body)
			reqFile.Close()
			a.log.Info().Str("FileName", reqFileName).Msg("IRMS request logged")
		}
	}

	var req model.FieldSignRequest
	err := ctx.BindJSON(&req)
	if err != nil {
		a.log.Err(err).Msg("invalid SignFile request")
		a.abortWithError(ctx, http.StatusBadRequest, model.ErrInvalidRequest)
		return
	}

	// get fresh list of certs
	certs, err := a.updateCertList()
	if err != nil {
		a.log.Err(err).Msg("ListHardwareCertificates failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}

	// find cert by thumbprint
	var cert *model.Certificate
	for i := range certs {
		if certs[i].Thumbprint == req.SigningCertificateThumbprint {
			cert = certs[i]
			break
		}
	}
	if cert == nil {
		a.log.Error().Str("Thumbprint", req.SigningCertificateThumbprint).Msg("Certificate not found")
		a.abortWithError(ctx, http.StatusBadRequest, model.ErrInvalidRequest)
		return
	}

	// request password from user
	pass := a.gui.RequestPass("[" + cert.SerialNumber + "] " + cert.X509Cert.Subject.CommonName)
	if pass == "" {
		a.log.Error().Str("Thumbprint", req.SigningCertificateThumbprint).Msg("Password is missing")
		a.abortWithError(ctx, http.StatusUnauthorized, model.ErrInvalidRequest)
		return
	}

	if req.Location == nil {
		s := "ME"
		req.Location = &s
	}

	spinStop, _ := a.gui.StartSpinner()
	defer func() {
		if spinStop != nil {
			spinStop()
		}
	}()

	// decode input data
	data, err := base64.StdEncoding.DecodeString(req.SigningFileStream)
	if err != nil {
		a.log.Err(err).Msg("Input data decoding failed")
		a.abortWithError(ctx, http.StatusBadRequest, err)
		return
	}
	req.SigningFileStream = "" // free mem

	// prepare stamp image
	stampText := []string{
		cert.SerialNumber[len(cert.SerialNumber)-8:],
		time.Now().Format("02.01.2006 15:04:05"),
	}
	stamp, err := a.crypto.MakeIRMSStamp(stampText, float64(req.XCoordinate), float64(req.YCoordinate))
	if err != nil {
		a.log.Err(err).Msg("Stamp image failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}

	// fill signature info
	signInfo := &model.SignatureInfo{
		Reason: req.Reason,
	}
	if req.Location != nil {
		signInfo.Location = *req.Location
	}
	if req.ContactInfo != nil {
		signInfo.ContactInfo = *req.ContactInfo
	}

	// sign document
	data, err = a.crypto.SignPDF(data, stamp, signInfo, cert, pass)
	if err != nil {
		a.log.Err(err).Msg("Sign failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}

	// save local copy of signed document
	outputFile, err := os.Create(fmt.Sprintf("irms-signed-%s.pdf", time.Now().Format("2006-01-02-150405")))
	if err != nil {
		a.log.Err(err).Msg("Signed file save failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}
	outputFile.Write(data)
	outputFile.Close()

	a.log.Info().Str("Thumbprint", req.SigningCertificateThumbprint).Msg("Document signed")

	// return doc to portal
	str := base64.StdEncoding.EncodeToString(data)
	resp := model.FieldSignResponse{
		SignedFileStream: &str,
	}
	// dirty hack: by some mystical reason IRMS expects not a regular JSON response, but a JSON wrapped into another JSON
	respBytes, _ := json.Marshal(resp)
	ctx.JSON(http.StatusOK, string(respBytes))
	// /dirty hack
}

// SignCustomFile signs any PDF file dropped into the app window
func (a *api) SignCustomFile(inputFilename, certSerial string) error {
	a.log.Info().Str("Filename", inputFilename).Str("CertSerial", certSerial).Msg("Signing PDF file")

	// select certificate
	certs, err := a.crypto.ListHardwareCertificates()
	if err != nil {
		a.log.Err(err).Msg("Cert list failed")
		return err
	}

	var cert *model.Certificate
	certSerial = strings.ToLower(certSerial)
	for i := range certs {
		if strings.ToLower(certs[i].SerialNumber) == certSerial {
			cert = certs[i]
			break
		}
	}
	if cert == nil {
		a.log.Error().Msg("Can't find certificate given by -sn or -thumb option")
		return err
	}

	// read input file
	data, err := os.ReadFile(inputFilename)
	if err != nil {
		a.log.Error().Str("in", inputFilename).Msg("Can't read input file, please specify it with -in option")
		return err
	}

	// make unique output file name
	var outputFilename, fileName, fileExt string
	dotPos := strings.LastIndex(inputFilename, ".")
	if dotPos < 0 {
		fileName = inputFilename
	} else {
		fileName = inputFilename[:dotPos]
		fileExt = inputFilename[dotPos:]
	}
	n := 0
	for n < 100 {
		f := fileName + ".signed." + time.Now().Format("2006-01-02-150405")
		if n > 0 {
			f += fmt.Sprintf("-%d", n)
		}
		f += fileExt
		_, err := os.Stat(f)
		if err != nil && os.IsNotExist(err) { // found unused name
			outputFilename = f
			break
		}
		n++
	}
	if outputFilename == "" {
		a.log.Error().Msg("Can't make unique output file name, please specify it manually with -out option")
		return model.ErrNotFound
	}

	// request password from user
	a.log.Info().Str("out", outputFilename).Msg("Requesting pass")
	pass := a.gui.RequestPass("[" + cert.SerialNumber + "] " + cert.X509Cert.Subject.CommonName)
	if pass == "" {
		a.log.Error().Msg("Password is missing")
		return model.ErrPasswordRequired
	}

	spinStop, _ := a.gui.StartSpinner()

	defer func() {
		if spinStop != nil {
			spinStop()
		}
	}()

	// prepare stamp image
	stamp, err := a.crypto.MakeCustomStamp([]string{
		"Digitally signed by",
		cert.IssuedTo,
		time.Now().Format("2006-01-02 15:04:05Z07:00"),
	})
	if err != nil {
		a.log.Error().Msg("MakeCustomStamp failed")
		return err
	}

	signInfo := &model.SignatureInfo{
		Name: cert.IssuedTo,
	}
	signed, err := a.crypto.SignPDF(data, stamp, signInfo, cert, pass)
	if err != nil {
		a.log.Err(err).Msg("SignCustomPDF failed")
		return err
	}

	a.log.Info().Str("out", outputFilename).Msg("Saving PDF...")
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		a.log.Err(err).Str("out", outputFilename).Msg("File save failed")
		return err
	}
	outputFile.Write(signed)
	outputFile.Close()

	a.log.Info().Str("out", outputFilename).Msg("PDF signed successfully!")
	return nil
}
