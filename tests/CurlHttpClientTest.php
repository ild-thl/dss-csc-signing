<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Exception\HttpException;
use IsyThl\Signing\Http\CurlHttpClient;
use PHPUnit\Framework\TestCase;

final class CurlHttpClientTest extends TestCase {
    public function test_json_and_form_requests_are_encoded_and_tls_options_forwarded(): void {
        $requests = [];
        $client = new CurlHttpClient(static function(string $url, string $body, string $contentType, array $headers, array $tlsOptions) use (&$requests): array {
            $requests[] = compact('url', 'body', 'contentType', 'headers', 'tlsOptions');
            return ['body' => '{"ok":true}', 'status' => 200, 'error' => ''];
        });

        $this->assertSame(['ok' => true], $client->postJson('https://example.test/json', ['name' => 'value'], ['X-Test: yes'], ['certificate' => '/client.crt']));
        $this->assertSame(['ok' => true], $client->postForm('https://example.test/form', ['name' => 'value']));
        $this->assertSame('application/json', $requests[0]['contentType']);
        $this->assertSame('{"name":"value"}', $requests[0]['body']);
        $this->assertSame('/client.crt', $requests[0]['tlsOptions']['certificate']);
        $this->assertSame('name=value', $requests[1]['body']);
    }

    public function test_non_success_and_malformed_responses_fail_with_typed_exceptions(): void {
        $client = new CurlHttpClient(static fn(): array => ['body' => '{"error":"private"}', 'status' => 500, 'error' => 'server']);
        try {
            $client->postJson('https://example.test', []);
            $this->fail('Expected an HTTP exception.');
        } catch (HttpException $exception) {
            $this->assertSame(500, $exception->statusCode);
            $this->assertStringNotContainsString('private', $exception->getMessage());
        }

        $client = new CurlHttpClient(static fn(): array => ['body' => 'not-json', 'status' => 200, 'error' => '']);
        $this->expectException(HttpException::class);
        $client->postJson('https://example.test', []);
    }
}
