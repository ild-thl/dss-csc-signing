<?php

declare(strict_types=1);

namespace IsyThl\Signing\Dss;

use IsyThl\Signing\Exception\ValidationException;
use IsyThl\Signing\DocumentValidatorInterface;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\ValidationResult;

final class DssValidator implements DocumentValidatorInterface {

    public function __construct(
        private HttpClientInterface $httpClient,
        private string $serviceUrl,
        private string $validationPath = '/validation/validateDocument'
    ) {
        if ($serviceUrl === '' || $validationPath === '') {
            throw new ValidationException('DSS validation endpoint is not configured.');
        }
    }

    public function validate(string $signedDocument): ValidationResult {
        if ($signedDocument === '') {
            throw new ValidationException('Signed document must not be empty.');
        }
        $report = $this->httpClient->postJson(
            rtrim($this->serviceUrl, '/') . $this->validationPath,
            ['signedDocument' => ['bytes' => base64_encode($signedDocument)]]
        );
        foreach (
            [
                'valid', 'qualified', 'certificateTrusted', 'revocationValid', 'timestampValid', 'trustedListValid',
                'certificatePurposeValid', 'signingTimeQualified',
            ] as $field
        ) {
            if (!isset($report[$field]) || !is_bool($report[$field])) {
                throw new ValidationException('DSS validation response is missing: ' . $field, $report);
            }
        }
        $evidence = $report['evidenceIdentifiers'] ?? [];
        if (
            !is_array($evidence)
            || $evidence === []
            || array_filter($evidence, static fn($value): bool => !is_string($value) || $value === '')
        ) {
            throw new ValidationException('DSS validation evidence identifiers are malformed.', $report);
        }
        $result = new ValidationResult(
            $report['valid'],
            $report['qualified'],
            $report,
            array_values($evidence)
        );
        if (
            !$result->isValid() || !$result->isQualified() || !$report['certificateTrusted']
            || !$report['revocationValid'] || !$report['timestampValid'] || !$report['trustedListValid']
            || !$report['certificatePurposeValid'] || !$report['signingTimeQualified']
        ) {
            throw new ValidationException('DSS validation did not meet the qualified issuance policy.', $report);
        }
        return $result;
    }
}
