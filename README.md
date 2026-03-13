# IRMSigner

Replacement for proprietary `IRMSDigitalSignatureApi` application, used in the state electronic document management of Montenegro. 

This application was developed by reverse-engineering of intercepted communication between IRMS portal and original app. 

No code from original software was used.

Running in background it listens to requests from IRMS portal web-app, opened in browser. 

Currently it serves two types of requests:

* List PKCS11 certificates installed on hardware cryptographic device (USB-Token);
* Sign PDF documents with selected certificate (PAdES standart).

Differences from the original software:

* Open-source
* Runs in Linux
* Displays certificate list
* Saves local copy of signed document

## Requirements

* PKCS11 hardware token (tested with `SafeNet eToken 5100`, issued by `Pošta CG`)
* Browser should have permission to access local network (it sends requests to the local port 8984)

## Usage

Just run the app, it will start in minimized state just to give you a possibility to view certificate list and close app when you don't need it anymore.

Insert your token and you'll see the list of certificates installed in it. Only CC certificates, usable for signing, are shown.

When browser with open IRMS portal sends a document sign request, you will be asked to enter the token password. 
Application will not count unsuccessfull attempts, so it's up to you.

## Config

App tries to read `config.yml` in current directory. If it's not found, default values are used.

Config example with default values:

```yaml
listen:           ":8984"                            # port to listen, no need to change
pkcs11_lib:       "/usr/lib/opensc-pkcs11.so"        # pkcs11 library name
stamp_background: "./img/stamp_bg.png"               # background image of stamp placed in signed PDF documents 
font:             "./img/LiberationSans-Regular.ttf" # font of stamp text 
font_size:        14                                 # font size of stamp text
```

## Building requirements

* golang >= 1.25
* libudev-dev
* opensc-pkcs11 >= 0.26.1 - critical, earlier versions are bugged and totally unusable

