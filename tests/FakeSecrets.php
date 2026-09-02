<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Security\SecretResolverInterface;

final class FakeSecrets implements SecretResolverInterface {

    public function resolve(string $name): string {
        return $name === 'client_secret' ? 'client-secret' : '/resolved/' . $name;
    }
}
