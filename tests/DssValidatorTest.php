<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Dss\DssValidator;
use IsyThl\Signing\Exception\ValidationException;
use IsyThl\Signing\Http\HttpClientInterface;
use PHPUnit\Framework\TestCase;

final class DssValidatorTest extends TestCase {

    public function test_validation_requires_qualification_evidence(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => ['sig-1', 'ts-1'],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $result = $validator->validate('{"signed":true}');

        $this->assertTrue($result->isValid());
        $this->assertTrue($result->isQualified());
        $this->assertSame(['sig-1', 'ts-1'], $result->evidenceIdentifiers());
        $this->assertSame('eyJzaWduZWQiOnRydWV9', $client->documentBytes);
    }

    public function test_cryptographic_validity_without_qualification_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => false,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_malformed_validation_evidence_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => ['sig-1', 42],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_invalid_certificate_purpose_fails_qualified_policy(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => false,
            'signingTimeQualified' => true,
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_empty_validation_evidence_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => [],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }
}
