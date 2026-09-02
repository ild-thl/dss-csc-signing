<?php

declare(strict_types=1);

namespace IsyThl\Signing\Http;

use IsyThl\Signing\Exception\HttpException;
use JsonException;

final class CurlHttpClient implements HttpClientInterface {
    /**
     * @param callable(string, string, string, array<int, string>, array<string, string>): array{body: string|false, status: int, error: string} $request
     */
    public function __construct(private $request = null) {
        $this->request ??= static function(string $url, string $body, string $contentType, array $headers, array $tlsOptions): array {
            $curl = curl_init($url);
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => array_merge($headers, ['Content-Type: ' . $contentType]),
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => 30,
            ]);
            if (!empty($tlsOptions['certificate'])) {
                curl_setopt($curl, CURLOPT_SSLCERT, $tlsOptions['certificate']);
            }
            if (!empty($tlsOptions['key'])) {
                curl_setopt($curl, CURLOPT_SSLKEY, $tlsOptions['key']);
            }
            if (!empty($tlsOptions['ca_info'])) {
                curl_setopt($curl, CURLOPT_CAINFO, $tlsOptions['ca_info']);
            }
            $response = curl_exec($curl);
            $result = [
                'body' => $response,
                'status' => (int) curl_getinfo($curl, CURLINFO_HTTP_CODE),
                'error' => curl_error($curl),
            ];
            curl_close($curl);
            return $result;
        };
    }

    public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        try {
            $body = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new HttpException('Could not encode the HTTP JSON request.', 0, [], $exception);
        }
        return $this->post($url, $body, 'application/json', $headers, $tlsOptions);
    }

    public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        return $this->post($url, http_build_query($data, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded', $headers, $tlsOptions);
    }

    /** @return array<string, mixed> */
    private function post(string $url, string $body, string $contentType, array $headers, array $tlsOptions): array {
        $response = ($this->request)($url, $body, $contentType, $headers, $tlsOptions);
        if ($response['body'] === false || $response['status'] < 200 || $response['status'] >= 300) {
            throw new HttpException('HTTP request failed.', $response['status']);
        }
        if ($response['status'] === 204 && trim($response['body']) === '') {
            return [];
        }
        try {
            $decoded = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new HttpException('HTTP response was not valid JSON.', $response['status'], [], $exception);
        }
        if (!is_array($decoded)) {
            throw new HttpException('HTTP response must be a JSON object.', $response['status']);
        }
        return $decoded;
    }
}
