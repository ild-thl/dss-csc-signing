<?php

declare(strict_types=1);

namespace IsyThl\Signing;

final class ValidationResult {

    /**
     * @param array<string, mixed> $report
     * @param array<int, string> $evidenceIdentifiers
     */
    public function __construct(
        private bool $valid,
        private bool $qualified,
        private array $report = [],
        private array $evidenceIdentifiers = []
    ) {
    }

    public function isValid(): bool {
        return $this->valid;
    }

    public function isQualified(): bool {
        return $this->qualified;
    }

    /** @return array<string, mixed> */
    public function report(): array {
        return $this->report;
    }

    /** @return array<int, string> */
    public function evidenceIdentifiers(): array {
        return $this->evidenceIdentifiers;
    }
}
