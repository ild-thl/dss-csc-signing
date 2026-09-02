<?php

declare(strict_types=1);

namespace IsyThl\Signing\Security;

interface SecretResolverInterface {

    public function resolve(string $name): string;
}
