<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Http\HttpClientInterface;

final class FakeCscHttpClient implements HttpClientInterface {

    public array $requests = [];

    public function __construct(private array $responses) {
    }

    public function postJson(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        return $this->record('json', $url, $data, $headers, $tlsOptions);
    }

    public function postForm(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        return $this->record('form', $url, $data, $headers, $tlsOptions);
    }

    private function record(
        string $transport,
        string $url,
        array $data,
        array $headers,
        array $tlsOptions
    ): array {
        $this->requests[] = [
            'transport' => $transport,
            'path' => parse_url($url, PHP_URL_PATH),
            'data' => $data,
            'headers' => $headers,
            'tls_options' => $tlsOptions,
        ];
        $response = array_shift($this->responses);
        if ($response instanceof \Throwable) {
            throw $response;
        }
        return $response;
    }
}
