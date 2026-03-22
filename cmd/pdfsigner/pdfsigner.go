package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"

	"github.com/mannulus-immortalis/irmsigner/internal/config"
	"github.com/mannulus-immortalis/irmsigner/internal/cryptoservice"
	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

func main() {
	var err error
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	cfg, err := config.LoadConfig("config.yml")
	if err != nil {
		log.Err(err).Msg("Config load failed")
		return
	}

	var inputFilename, outputFilename string
	var certThumbprint, certSerial string
	var signatureText, password string
	flag.StringVar(&inputFilename, "in", "", "PDF file to sign")
	flag.StringVar(&outputFilename, "out", "", "new signed PDF file")
	flag.StringVar(&certSerial, "sn", "", "select certificate by serial number (mutual exclusive with -thumbprint)")
	flag.StringVar(&certThumbprint, "thumb", "", "select certificate by thumbprint (mutual exclusive with -serial)")
	flag.StringVar(&signatureText, "sig", "", "override default signature text")
	flag.StringVar(&password, "pass", "", "UNSAFE: certificate password (will be asked if not specified)")
	flag.Parse()

	// Crypto
	crypto, err := cryptoservice.New(cfg)
	if err != nil {
		log.Err(err).Msg("Crypto init failed")
		return
	}

	certs, err := crypto.ListHardwareCertificates()
	if err != nil {
		log.Err(err).Msg("Cert list failed")
		return
	}

	if inputFilename == "" { // list certificates
		fmt.Println("Available certificates:")
		fmt.Println("Serial\t\tThumbprint\t\t\t\t\tIssued to\t\tValid till")
		for _, c := range certs {
			fmt.Printf("%s\t%s\t%s\t%s\n",
				c.SerialNumber,
				c.Thumbprint,
				c.IssuedTo,
				c.ValidTill.Format(time.DateOnly),
			)
		}
		return
	}

	_, err = os.Stat(inputFilename)
	if err != nil {
		log.Error().Str("in", inputFilename).Msg("Can't find input file, please specify it with -in option")
		return
	}

	data, err := os.ReadFile(inputFilename)
	if err != nil {
		log.Error().Str("in", inputFilename).Msg("Can't read input file, please specify it with -in option")
		return
	}

	// make unique output file name
	if outputFilename == "" {
		var fileName, fileExt string
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
			log.Error().Msg("Can't make unique output file name, please specify it manually with -out option")
			return
		}
	}

	// select certificate
	var cert *model.Certificate
	if certThumbprint != "" {
		certThumbprint = strings.ToLower(certThumbprint)
		for i := range certs {
			if strings.ToLower(certs[i].Thumbprint) == certThumbprint {
				cert = certs[i]
				break
			}
		}
	}
	if certSerial != "" {
		certSerial = strings.ToLower(certSerial)
		for i := range certs {
			if strings.ToLower(certs[i].SerialNumber) == certSerial {
				cert = certs[i]
				break
			}
		}
	}
	if cert == nil {
		log.Error().Msg("Can't find certificate given by -sn or -thumb option")
		return
	}

	// prepare stamp image
	stamp, err := crypto.MakeCustomStamp([]string{
		"Digitally signed by",
		cert.IssuedTo,
		time.Now().Format("2006-01-02 15:04:05Z07:00"),
	})
	if err != nil {
		log.Error().Msg("MakeCustomStamp failed")
		return
	}

	signInfo := &model.SignatureInfo{
		Name: cert.IssuedTo,
	}
	signed, err := crypto.SignPDF(data, stamp, signInfo, cert, password)
	if err != nil {
		log.Err(err).Msg("SignCustomPDF failed")
		return
	}

	outputFile, err := os.Create(outputFilename)
	if err != nil {
		log.Err(err).Str("out", outputFilename).Msg("File save failed")
		return
	}
	outputFile.Write(signed)
	outputFile.Close()

	log.Info().Str("out", outputFilename).Msg("PDF signed successfully!")

	return
}
