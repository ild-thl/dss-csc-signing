# DSS/CSC Signing

`isy-thl/dss-csc-signing` is a framework-independent PHP package for qualified
JAdES signing workflows that combine:

- a Digital Signature Services (DSS) API for document timestamps, JAdES
  orchestration, and validation; and
- a Cloud Signature Consortium (CSC) v2 API backed by a remote qualified
  signature creation device for hash signing and certificate operations.

The package accepts serialized JSON document bytes and returns serialized signed
document bytes. It does not depend on Moodle, Laravel, ELM, Open Badges, or any
other document model. Applications provide their own document mapping and
configuration.

## Current scope

The package currently provides:

- DSS signing orchestration for JAdES baseline LTA documents;
- CSC v2 hash signing, timestamping, certificate discovery, PKCE, polling, and
  access-token revocation;
- RSA and ECDSA signing algorithm selection;
- certificate-chain forwarding to DSS;
- DSS validation before a signed document is released; and
- injectable HTTP and secret-resolution boundaries for application integration.

The intended signing sequence is:

```text
DSS document timestamp
  -> DSS getDataToSign
  -> CSC signHash
  -> DSS signDocument
  -> DSS validation
```

## Limitations

This is an early package release. It does not currently provide:

- document-format models or serializers;
- a Laravel or Moodle integration package;
- a live QTSP, DSS, or sandbox environment;
- provider-specific production configuration;
- persistent audit storage or an application logging implementation;
- automatic certificate renewal or outage recovery; or
- a guarantee that every DSS or CSC provider uses the same endpoint and
  response profile.

The application must verify the selected QTSP, QSCD, TSA, DSS deployment,
trusted-list configuration, certificate purpose, and validation response schema
before production issuance. Private keys, client secrets, access tokens, and
mTLS material must be resolved at runtime and must not be committed or logged.
CSC OAuth and API endpoints must use HTTPS; the package rejects non-HTTPS
endpoints during provider construction.

## Requirements

- PHP 8.1 or newer
- PHP cURL extension
- PHP OpenSSL extension
- PHP DOM/XML extension for development and PHPUnit
- A DSS service exposing the required document-signing and validation APIs
- A CSC v2-compatible signing provider and authorized credential

## Installation

```sh
composer require isy-thl/dss-csc-signing
```

The package is framework-independent. Applications instantiate the DSS signer,
CSC provider, HTTP client, secret resolver, and certificate/validation
boundaries according to their own configuration. See the classes and tests for
small fake-client examples.

## Application wiring

The signing package accepts serialized document bytes, so an application owns
document construction and serialization. A framework-neutral application can
wire the package like this after loading its profile and secret configuration:

```php
$http = new CurlHttpClient();
$secrets = new EnvironmentSecretResolver();
$csc = new CscSigningProvider($profile, $http, $secrets);
$validator = new DssValidator($http, $dssUrl);
$signer = new DssSigner(
  $http,
  $csc,
  $dssUrl,
  $csc,
  $csc,
  null,
  $validator
);

$signedDocument = $signer->sign($documentJson, $trustedMetadata);
```

The application should supply its own document mapper, configuration binding,
secret storage, logging, queueing, retry policy, and audit persistence.

## Development and testing

Clone the repository and install development dependencies:

```sh
git clone https://github.com/ild-thl/isy-dss-csc-signing.git
cd isy-dss-csc-signing
composer install
vendor/bin/phpunit -c phpunit.xml
```

The test suite uses fake HTTP clients and signing providers. It does not call a
live DSS service, QTSP, TSA, or private key. Run Composer validation as part of
release preparation:

```sh
composer validate --strict
composer lint
composer format
composer style
composer analyse
```

## Debug logging

Pass an implementation of `LoggerInterface` to `CurlHttpClient` to receive
opt-in request lifecycle diagnostics. The package logs only HTTP method,
endpoint path, status, and transport errors. It does not log request bodies,
headers, tokens, hashes, signatures, certificates, or secret values.

The Moodle integration exposes this through the `Enable CSC/DSS debug logging`
setting and sends the diagnostics to Moodle developer debugging. Enable it only
while troubleshooting a controlled development or test environment.

## Releases

Releases are published from Git tags using semantic versioning. The `main`
branch and version tags are tested by GitHub Actions. Packagist should be
connected to the GitHub repository so tagged releases are imported
automatically.

## References

- [Digital Signature Service (DSS)](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109107/Digital+Signature+Service+-+DSS)
- [Cloud Signature Consortium API v2.0.0.2](https://cloudsignatureconsortium.org/wp-content/uploads/2023/04/csc-api-v2.0.0.2.pdf)

## License

GPL-3.0-or-later
