<?php

declare(strict_types=1);

namespace IsyThl\Signing\Http;

use IsyThl\Signing\Exception\HttpException;
use IsyThl\Signing\Logging\LoggerInterface;
use JsonException;

final class CurlHttpClient implements HttpClientInterface {

    /** @var callable|null */
    private $request;

    /**
    * @param callable(
    *     string, string, string, array<int, string>, array<string, string>
    * ): array{body: string|false, status: int, error: string} $request
     */
    public function __construct(
        ?callable $request = null,
        private ?LoggerInterface $logger = null,
        private string $userAgent = 'isy-thl/dss-csc-signing'
    ) {
        $this->request = $request ?? function (
            string $url,
            string $body,
            string $contentType,
            array $headers,
            array $tlsOptions
        ): array {
            $curl = curl_init($url);
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => array_merge($headers, [
                    'Content-Type: ' . $contentType,
                ]),
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

    /**
     * @param array<string, mixed> $data
     * @param array<int, string> $headers
     * @param array<string, string|null> $tlsOptions
     * @return array<string, mixed>
     */
    public function postJson(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        try {
            $body = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new HttpException('Could not encode the HTTP JSON request.', 0, [], $exception);
        }
        return $this->post($url, $body, 'application/json', $headers, $tlsOptions);
    }

    /**
     * @param array<string, mixed> $data
     * @param array<int, string> $headers
     * @param array<string, string|null> $tlsOptions
     * @return array<string, mixed>
     */
    public function postForm(string $url, array $data, array $headers = [], array $tlsOptions = []): array {
        return $this->post(
            $url,
            http_build_query($data, '', '&', PHP_QUERY_RFC3986),
            'application/x-www-form-urlencoded',
            $headers,
            $tlsOptions
        );
    }

    /**
     * @param array<int, string> $headers
     * @param array<string, string|null> $tlsOptions
     * @return array<string, mixed>
     */
    private function post(string $url, string $body, string $contentType, array $headers, array $tlsOptions): array {
        if (!$this->hasHeader($headers, 'User-Agent')) {
            $headers[] = 'User-Agent: ' . $this->userAgent;
        }
        $this->logger?->debug('HTTP request started.', [
            'method' => 'POST',
            'path' => (string) (parse_url($url, PHP_URL_PATH) ?: '/'),
            'content_type' => $contentType,
        ]);
        $response = ($this->request)($url, $body, $contentType, $headers, $tlsOptions);
        $errorDetails = $this->errorDetails($response['body']);
        $this->logger?->debug('HTTP request completed.', [
            'method' => 'POST',
            'path' => (string) (parse_url($url, PHP_URL_PATH) ?: '/'),
            'status' => $response['status'],
            'transport_error' => $response['error'] !== '' ? $response['error'] : null,
            'provider_error' => $errorDetails,
        ]);
        if ($response['body'] === false || $response['status'] < 200 || $response['status'] >= 300) {
            $detail = $response['error'] !== '' ? '; transport error: ' . $response['error'] : '';
            $providerDetail = $errorDetails !== null ? '; provider error: ' . $errorDetails : '';
            throw new HttpException(
                'HTTP request failed with status ' . $response['status'] . $detail . $providerDetail . '.',
                $response['status']
            );
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

    /** @param array<int, string> $headers */
    private function hasHeader(array $headers, string $name): bool {
        foreach ($headers as $header) {
            if (str_starts_with(strtolower($header), strtolower($name) . ':')) {
                return true;
            }
        }
        return false;
    }

    private function errorDetails(string|false $body): ?string {
        if (!is_string($body)) {
            return null;
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            $detail = trim(preg_replace('/\s+/', ' ', $body) ?? '');
            if ($detail === '') {
                return null;
            }
            return $this->redact($detail);
        }
        $error = isset($decoded['error']) && is_string($decoded['error']) ? $decoded['error'] : null;
        $description = isset($decoded['error_description']) && is_string($decoded['error_description'])
            ? $decoded['error_description']
            : null;
        if ($error === null && $description === null) {
            return null;
        }
        $detail = implode(
            ': ',
            array_filter([$error, $description])
        );
        return $this->redact($detail);
    }

    private function redact(string $detail): string {
        $detail = preg_replace(
            '/(token|secret|code|hash|signature)\s*[:=]\s*[^,;\s]+/i',
            '$1=[redacted]',
            $detail
        ) ?? $detail;
        return substr($detail, 0, 200);
    }
}
