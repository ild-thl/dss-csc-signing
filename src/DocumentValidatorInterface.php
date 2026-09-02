<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface DocumentValidatorInterface {

    public function validate(string $signedDocument): ValidationResult;
}
