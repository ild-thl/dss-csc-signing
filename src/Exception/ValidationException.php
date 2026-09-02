<?php

declare(strict_types=1);

namespace IsyThl\Signing\Exception;

final class ValidationException extends SigningException {

    /** @param array<string, mixed> $report */
    public function __construct(string $message, public readonly array $report = []) {
        parent::__construct($message);
    }
}
