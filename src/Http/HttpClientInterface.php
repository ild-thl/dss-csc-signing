<?php

declare(strict_types=1);

namespace IsyThl\Signing\Http;

interface HttpClientInterface {

    /**
     * @return array<string, mixed>
     */
    /**
     * @param array<string, mixed> $data
     * @param array<int, string> $headers
     * @param array<string, string|null> $tlsOptions
     * @return array<string, mixed>
     */
    public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array;

    /**
     * @return array<string, mixed>
     */
    /**
     * @param array<string, mixed> $data
     * @param array<int, string> $headers
     * @param array<string, string|null> $tlsOptions
     * @return array<string, mixed>
     */
    public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array;
}
