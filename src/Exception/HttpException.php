<?php

declare(strict_types=1);

namespace IsyThl\Signing\Exception;

final class HttpException extends SigningException {

    /** @param array<string, mixed> $responseData */
    public function __construct(
        string $message,
        public readonly int $statusCode = 0,
        public readonly array $responseData = [],
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 0, $previous);
    }
}
