# IRMSigner

Replacement for proprietary `IRMSDigitalSignatureApi` application, used in the state electronic document management of Montenegro. 

This application was developed by reverse-engineering of intercepted communication between IRMS portal and original app. 

No code from original software was used.

Running in background it listens to requests from IRMS portal web-app, opened in browser. 

Currently it serves two types of requests:

* List PKCS11 certificates installed on hardware cryptographic device (USB-Token);
* Sign PDF documents with selected certificate (PAdES standart).

## Requirements

* PKCS11 hardware token (tested with `SafeNet eToken 5100`, issued by `Pošta CG`)
* PKCS11 driver: `opensc` library, `SafeNet Authentication Client` or `SafeNet Minidriver`, or something else. Tested with `opensc`.
* Browser should have permission to access local network (it sends requests to the local port `8984`)

## Installation

1. Copy all files from repository to any place you want.
2. Install PKCS11 software
3. Find pkcs11 library path: usually they are installed into `/usr/lib/pkcs11/` directory. For example `/usr/lib/pkcs11/opensc-pkcs11.so` or `/usr/lib/pkcs11/libIDPrimePKCS11.so`
4. Update your `config.yml` file: set `pkcs11_lib` parameter and check other paths - all mentioned files should present.

## Usage

Run the app.

Insert your token and you'll see the list of certificates installed in it. Only "Content Commitment / Non Repudiation" certificates, usable for signing, are shown.

### Signing any PDF document

IRMS portal requires you to sign each PDF file you upload there.

Select certificate from the list (just click it and it will be highlighted).

Drag-and-drop your PDF file into application window - it's name will be shown under certificates list and "Sign file" button will be enabled.

Press "Sign button" and enter your token password. Signed file will be named as original with added suffix `.signed.YYYY-MM-DD-hhmmss`.

### Working with IRMS portal

When browser with open IRMS portal sends a document sign request, you will be asked to enter the token password.

## Config

App tries to read `config.yml` in current directory. If it's not found, default values are used.

Config example with default values:

```yaml
listen:           ":8984"                            # port to listen, no need to change
pkcs11_lib:       "/usr/lib/pkcs11/opensc-pkcs11.so" # pkcs11 library name
stamp_background: "./img/stamp_bg.png"               # background image of stamp placed in signed PDF documents 
font:             "./img/LiberationSans-Regular.ttf" # font of stamp text 
log_requests:     true                               # save incoming requests in *.json files
```

## Building requirements

* golang >= 1.25
* libudev-dev
* opensc-pkcs11 >= 0.26.1 - critical, earlier versions are bugged and totally unusable
* OR SafenetAuthenticationClient >= 10.9
