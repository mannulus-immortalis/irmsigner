# Refactor next steps

This document records the recommended follow-up work after introducing the application-layer interfaces in `internal/app`.

## 1. Run and fix the application-layer tests

```bash
gofmt -w internal/app
go test ./internal/app
go test ./...
```

Confirm that the new interfaces compile against the existing repository.

## 2. Adapt the existing crypto service

Make `cryptoservice.cryptoservice` explicitly satisfy `app.CryptoPort`:

```go
var _ app.CryptoPort = (*cryptoservice)(nil)
```

Keep the implementation behavior unchanged.

## 3. Adapt the GTK GUI

Add compile-time verification:

```go
var _ app.GUIAdapter = (*gui.gui)(nil)
```

Eventually move the interface out of `internal/model/gui.go` so `model` contains data types rather than application ports.

## 4. Wire the application layer into `internal/api`

- Add an `*app.UseCase` field to the API.
- Change certificate refresh to call `UseCase.ListCertificates()`.
- Migrate custom PDF signing first with `UseCase.SignDocument(...)`.
- Preserve existing password prompts, spinner behavior, output naming, and response formats.

## 5. Extract certificate selection

Add reusable helpers such as:

```go
func FindCertificateByThumbprint(...)
func FindCertificateBySerial(...)
```

Normalize case consistently and return `model.ErrCertNotFound` instead of returning a potentially unrelated nil error in `SignCustomFile`.

## 6. Extract PDF output naming

Move duplicate filename-generation logic from `cmd/pdfsigner` and `api.SignCustomFile` into a small filesystem/application helper.

Add tests for:

- files with extensions
- files without extensions
- existing timestamped outputs
- multiple collisions
- paths containing multiple dots

## 7. Migrate the IRMS HTTP signing flow

Move signing orchestration out of `internal/api/handlers.go`.

Keep HTTP-specific responsibilities in the handler:

- decode JSON
- decode base64
- map errors to status codes
- encode the response

Keep application responsibilities in the use case:

- select certificate
- create the stamp
- sign the document
- build signature metadata

## 8. Add request validation

Validate:

- non-empty signing stream
- non-empty certificate thumbprint
- valid coordinates
- supported signing options

Avoid panics such as:

```go
cert.SerialNumber[len(cert.SerialNumber)-8:]
```

when the serial number is shorter than eight characters.

## 9. Make certificate response conversion safe

`GetCerts` currently assumes that `X509Cert` is non-nil and that `PolicyIdentifiers` contains at least one item. Add safe conversion helpers so malformed or unusual certificates cannot crash the HTTP handler.

## 10. Improve lifecycle handling

- Make `api.Close()` safe if the server has not started.
- Prefer `http.Server.Shutdown()` with a timeout where appropriate.
- Stop signal notification with `signal.Stop(sig)`.
- Ensure USB event listeners terminate when the application context is canceled.

## 11. Separate model interfaces from model data

Move these out of `internal/model`:

- `CryptoService`
- `GUI`
- `FileDropFunc`

Keep `internal/model` focused on:

- `Certificate`
- `StampImage`
- `SignatureInfo`
- request/response DTOs
- configuration data

## 12. Split `cryptoservice.go`

A potential eventual structure is:

```text
internal/cryptoservice/
  service.go       # application-facing orchestration
  certificates.go  # PKCS11 certificate discovery
  signer.go        # token signer creation
  stamps.go        # stamp rendering
  pages.go         # PDF page-size helpers
```

## Suggested implementation order

1. Run formatting and tests.
2. Add compile-time interface assertions.
3. Extract certificate lookup and output filename helpers.
4. Wire `internal/api` through `internal/app.UseCase`.
5. Add handler and use-case tests.
6. Improve lifecycle and validation behavior.
7. Split the remaining large packages once behavior is covered.
