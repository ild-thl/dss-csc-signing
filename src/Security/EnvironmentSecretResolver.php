<?php

declare(strict_types=1);

namespace IsyThl\Signing\Security;

use IsyThl\Signing\Exception\SigningException;

final class EnvironmentSecretResolver implements SecretResolverInterface {
    public function resolve(string $name): string {
        if ($name === '') {
            throw new SigningException('Secret name must not be empty.');
        }
        $value = getenv($name);
        if ($value === false || $value === '') {
            throw new SigningException('Required secret is not available: ' . $name);
        }
        return $value;
    }
}
