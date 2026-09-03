<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Exception\HttpException;
use IsyThl\Signing\Http\CurlHttpClient;
use IsyThl\Signing\Logging\LoggerInterface;
use PHPUnit\Framework\TestCase;

final class CurlHttpClientTest extends TestCase {

    public function test_timeouts_must_be_positive(): void {
        $this->expectException(\InvalidArgumentException::class);
        new CurlHttpClient(null, null, 'test-agent', 0);
    }

    public function test_json_and_form_requests_are_encoded_and_tls_options_forwarded(): void {
        $requests = [];
        $client = new CurlHttpClient(static function (
            string $url,
            string $body,
            string $contentType,
            array $headers,
            array $tlsOptions
        ) use (&$requests): array {
            $requests[] = compact('url', 'body', 'contentType', 'headers', 'tlsOptions');
            return ['body' => '{"ok":true}', 'status' => 200, 'error' => ''];
        });

        $this->assertSame(
            ['ok' => true],
            $client->postJson(
                'https://example.test/json',
                ['name' => 'value'],
                ['X-Test: yes'],
                ['certificate' => '/client.crt']
            )
        );
        $this->assertSame(['ok' => true], $client->postForm('https://example.test/form', ['name' => 'value']));
        $this->assertSame('application/json', $requests[0]['contentType']);
        $this->assertSame('{"name":"value"}', $requests[0]['body']);
        $this->assertContains('User-Agent: isy-thl/dss-csc-signing', $requests[0]['headers']);
        $this->assertSame('/client.crt', $requests[0]['tlsOptions']['certificate']);
        $this->assertSame('name=value', $requests[1]['body']);
    }

    public function test_non_success_and_malformed_responses_fail_with_typed_exceptions(): void {
        $client = new CurlHttpClient(
            static fn(): array => [
                'body' => '{"error":"invalid_grant","error_description":"code=private"}',
                'status' => 500,
                'error' => 'server',
            ]
        );
        try {
            $client->postJson('https://example.test', []);
            $this->fail('Expected an HTTP exception.');
        } catch (HttpException $exception) {
            $this->assertSame(500, $exception->statusCode);
            $this->assertStringContainsString('status 500', $exception->getMessage());
            $this->assertStringContainsString('invalid_grant', $exception->getMessage());
            $this->assertStringContainsString('code=[redacted]', $exception->getMessage());
            $this->assertStringNotContainsString('code=private', $exception->getMessage());
        }

        $client = new CurlHttpClient(static fn(): array => [
            'body' => 'DSS failure: signature=private-signature; detail=certificate rejected',
            'status' => 500,
            'error' => '',
        ]);
        try {
            $client->postJson('https://example.test', []);
            $this->fail('Expected an HTTP exception.');
        } catch (HttpException $exception) {
            $this->assertStringContainsString('DSS failure', $exception->getMessage());
            $this->assertStringContainsString('signature=[redacted]', $exception->getMessage());
            $this->assertStringNotContainsString('private-signature', $exception->getMessage());
        }

        $client = new CurlHttpClient(static fn(): array => ['body' => 'not-json', 'status' => 200, 'error' => '']);
        $this->expectException(HttpException::class);
        $client->postJson('https://example.test', []);
    }

    public function test_debug_logging_contains_transport_metadata_but_not_request_data(): void {
        $messages = [];
        $client = new CurlHttpClient(
            static fn(): array => ['body' => '{"error":"private"}', 'status' => 400, 'error' => ''],
            new class ($messages) implements LoggerInterface {
                public function __construct(private array &$messages) {
                }

                public function debug(string $message, array $context = []): void {
                    $this->messages[] = [$message, $context];
                }
            }
        );

        try {
            $client->postForm(
                'https://example.test/oauth2/token',
                ['client_secret' => 'secret', 'code' => 'authorization-code']
            );
        } catch (HttpException) {
        }

        $this->assertSame('/oauth2/token', $messages[0][1]['path']);
        $this->assertSame(400, $messages[1][1]['status']);
        $this->assertArrayNotHasKey('body', $messages[0][1]);
        $this->assertArrayNotHasKey('headers', $messages[0][1]);
    }
}
