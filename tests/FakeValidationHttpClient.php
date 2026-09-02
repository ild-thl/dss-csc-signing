<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Http\HttpClientInterface;

final class FakeValidationHttpClient implements HttpClientInterface {

    public string $documentBytes = '';

    public function __construct(private array $response) {
    }

    public function postJson(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        $this->documentBytes = $data['signedDocument']['bytes'];
        return $this->response;
    }

    public function postForm(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        throw new \LogicException('form transport is not used');
    }
}
