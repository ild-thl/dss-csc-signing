<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Dss\DssSigner;
use IsyThl\Signing\CertificateProviderInterface;
use IsyThl\Signing\DocumentValidatorInterface;
use IsyThl\Signing\ValidationResult;
use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\SigningProviderInterface;
use IsyThl\Signing\TimestampProviderInterface;
use PHPUnit\Framework\TestCase;

final class DssSignerTest extends TestCase {
    public function test_signing_preserves_dss_bytes_and_order(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $timestamp = new class($calls) implements TimestampProviderInterface {
            public function __construct(private array &$calls) {
            }

            public function timestamp(string $document): array {
                $this->calls[] = 'timestamp';
                return [
                    'bytes' => 'timestamp-token',
                    'digestAlgorithm' => 'SHA512',
                    'timestampContainerForm' => null,
                ];
            }
        };
        $provider = new class($calls) implements SigningProviderInterface {
            public string $input = '';

            public function __construct(private array &$calls) {
            }

            public function sign(string $data): string {
                $this->calls[] = 'sign';
                $this->input = $data;
                return 'signature-bytes';
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $certificateProvider = new class implements CertificateProviderInterface {
            public function certificateData(): array {
                return [
                    'certificate' => 'certificate',
                    'chain' => ['certificate', 'intermediate-certificate'],
                ];
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', $certificateProvider, $timestamp);

        $result = $signer->sign('{"id":"credential","issuer":{"id":"untrusted"}}', [
            'issuer' => ['id' => 'trusted'],
            'issuanceDate' => '2030-01-01T00:00:00Z',
        ]);

        $this->assertSame('{"signed":true}', $result);
        $this->assertSame(['timestamp', 'getDataToSign', 'sign', 'signDocument'], $calls);
        $this->assertSame('dss-data-to-sign', $provider->input);
        $this->assertSame('trusted', $http->dataToSignDocument['issuer']['id']);
        $this->assertSame([
            base64_encode('certificate'),
            base64_encode('intermediate-certificate'),
        ], $http->certificateChain);
        $this->assertSame('JSON_SERIALIZATION', $http->jwsSerializationType);
        $this->assertTrue($http->base64UrlEncodedEtsiUComponents);
        $this->assertSame('RSA_SHA256', $http->signature['algorithm']);
        $this->assertSame(base64_encode('signature-bytes'), $http->signature['value']);
    }

    public function test_invalid_json_is_rejected_before_dependencies_are_called(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class implements SigningProviderInterface {
            public function sign(string $data): string {
                throw new \LogicException('must not sign');
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate');

        $this->expectException(SigningException::class);
        $signer->sign('{invalid');
        $this->assertSame([], $calls);
    }

    public function test_ecdsa_provider_selects_ecdsa_dss_encryption_algorithm(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class implements SigningProviderInterface {
            public function sign(string $data): string {
                return 'signature';
            }

            public function signatureAlgorithm(): string {
                return 'ECDSA_SHA256';
            }
        };
        $timestamp = new class implements TimestampProviderInterface {
            public function timestamp(string $document): array {
                return ['bytes' => 'timestamp'];
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate', $timestamp);

        $signer->sign('{"id":"credential"}');

        $this->assertSame('ECDSA', $http->encryptionAlgorithm);
    }

    public function test_signed_document_is_validated_before_it_is_returned(): void {
        $calls = [];
        $validator = new class($calls) implements DocumentValidatorInterface {
            public function __construct(private array &$calls) {
            }

            public function validate(string $signedDocument): ValidationResult {
                $this->calls[] = 'validate';
                return new ValidationResult(true, true);
            }
        };
        $signer = new DssSigner(
            new FakeDssHttpClient($calls),
            new class implements SigningProviderInterface {
                public function sign(string $data): string { return 'signature'; }
                public function signatureAlgorithm(): string { return 'RSA_SHA256'; }
            },
            'https://dss.example',
            'certificate',
            new class implements TimestampProviderInterface {
                public function timestamp(string $document): array { return ['bytes' => 'timestamp']; }
            },
            null,
            $validator
        );

        $this->assertSame('{"signed":true}', $signer->sign('{"id":"credential"}'));
        $this->assertContains('validate', $calls);
    }
}

final class FakeDssHttpClient implements HttpClientInterface {
    public array $dataToSignDocument = [];
    public array $signature = [];
    public array $certificateChain = [];
    public string $encryptionAlgorithm = '';
    public string $jwsSerializationType = '';
    public bool $base64UrlEncodedEtsiUComponents = false;

    public function __construct(private array &$calls) {
    }

    public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        if (str_ends_with($url, '/timestampDocument')) {
            $this->calls[] = 'dss-timestamp';
            return ['bytes' => base64_encode('timestamp-token')];
        }
        if (str_ends_with($url, '/getDataToSign')) {
            $this->calls[] = 'getDataToSign';
            $this->dataToSignDocument = json_decode(base64_decode($data['toSignDocument']['bytes'], true), true);
            $this->certificateChain = array_column($data['parameters']['certificateChain'], 'encodedCertificate');
            $this->encryptionAlgorithm = $data['parameters']['encryptionAlgorithm'];
            $this->jwsSerializationType = $data['parameters']['jwsSerializationType'];
            $this->base64UrlEncodedEtsiUComponents = $data['parameters']['base64UrlEncodedEtsiUComponents'];
            return ['bytes' => base64_encode('dss-data-to-sign')];
        }
        $this->calls[] = 'signDocument';
        $this->signature = $data['signatureValue'];
        return ['bytes' => base64_encode('{"signed":true}')];
    }

    public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        throw new \LogicException('form transport is not used');
    }
}
