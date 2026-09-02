<?php

declare(strict_types=1);

namespace IsyThl\Signing\Logging;

interface LoggerInterface {

    /** @param array<string, scalar|null> $context */
    public function debug(string $message, array $context = []): void;
}
