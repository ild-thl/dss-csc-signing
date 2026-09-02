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
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }
}

final class FakeValidationHttpClient implements HttpClientInterface {
    public string $documentBytes = '';

    public function __construct(private array $response) {
    }

    public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        $this->documentBytes = $data['signedDocument']['bytes'];
        return $this->response;
    }

    public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        throw new \LogicException('form transport is not used');
    }
}
