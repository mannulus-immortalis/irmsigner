package api

import (
	"encoding/base64"
	"net/http"

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

	// sign document
	data, err := a.crypto.SignPDF(&req, cert, pass)
	if err != nil {
		if spinStop != nil {
			spinStop()
		}
		a.log.Err(err).Msg("Sign failed")
		a.abortWithError(ctx, http.StatusInternalServerError, err)
		return
	}
	if spinStop != nil {
		spinStop()
	}

	a.log.Info().Str("Thumbprint", req.SigningCertificateThumbprint).Msg("Document signed")

	// return doc to portal
	str := base64.StdEncoding.EncodeToString(data)
	resp := model.FieldSignResponse{
		SignedFileStream: &str,
	}
	ctx.JSON(http.StatusCreated, resp)
}
