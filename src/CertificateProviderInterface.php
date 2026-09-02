<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface CertificateProviderInterface {
    /**
     * @return array{certificate: string, chain: array<int, string>}
     */
    public function certificateData(): array;
}
