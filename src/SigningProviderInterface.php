<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface SigningProviderInterface {

    public function sign(string $data): string;

    public function signatureAlgorithm(): string;
}
