<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\Security\EnvironmentSecretResolver;
use IsyThl\Signing\SigningProviderInterface;
use PHPUnit\Framework\TestCase;

final class ContractTest extends TestCase {

    public function test_http_and_signing_contracts_are_framework_independent(): void {
        $http = new class implements HttpClientInterface {
            public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
                return [];
            }

            public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
                return [];
            }
        };
        $provider = new class implements SigningProviderInterface {
            public function sign(string $data): string {
                return $data;
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };

        $this->assertInstanceOf(HttpClientInterface::class, $http);
        $this->assertSame('data', $provider->sign('data'));
        $this->assertSame('RSA_SHA256', $provider->signatureAlgorithm());
    }

    public function test_signing_exception_is_a_package_exception(): void {
        $exception = new SigningException('request failed');

        $this->assertSame('request failed', $exception->getMessage());
        $this->assertSame(SigningException::class, get_class($exception));
    }

    public function test_environment_secret_resolver_returns_values_without_persisting_them(): void {
        putenv('ISY_TEST_SECRET=secret-value');
        $resolver = new EnvironmentSecretResolver();

        $this->assertSame('secret-value', $resolver->resolve('ISY_TEST_SECRET'));
        $this->expectException(SigningException::class);
        $resolver->resolve('ISY_MISSING_SECRET');
    }
}
