<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface TimestampProviderInterface {
    /**
     * @return array<string, mixed>
     */
    public function timestamp(string $document): array;
}
