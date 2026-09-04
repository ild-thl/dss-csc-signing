# Changelog

## 0.1.2 - 2026-09-04

- Added framework-independent DSS and CSC signing contracts, typed exceptions,
  HTTP transport, secret resolution, logging, and validation boundaries.
- Added DSS timestamping, `getDataToSign`, CSC hash signing, and final
  `signDocument` orchestration with qualified-validation release gating.
- Added CSC PKCE authorization, bounded polling, token revocation, timestamping,
  certificate discovery, certificate-chain validation, and RSA/ECDSA mapping.
- Added HTTPS-by-default transport, explicit isolated-development DSS HTTP
  opt-in, positive HTTP timeouts, malformed-response rejection, and safe
  redacted lifecycle logging.
- Added certificate-purpose and signing-time qualification checks, evidence
  identifier requirements, certificate fingerprint pinning, and strict JSON
  object validation.
- Added CI, Composer validation, PHP linting, PHPCS, PHPStan, PHPUnit, and
  production no-dev installation checks.

## 0.1.0 - Unreleased

- Initial framework-independent DSS and CSC JAdES signing package.
- CSC v2 hash signing, timestamping, certificate discovery, PKCE, polling, and
  revocation support.
- DSS JAdES orchestration and validation release gate.
- RSA and ECDSA signing algorithm support.