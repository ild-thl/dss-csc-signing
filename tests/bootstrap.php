<?php

spl_autoload_register(static function (string $class): void {
    $prefixes = [
        'IsyThl\\Signing\\Tests\\' => __DIR__ . '/',
        'IsyThl\\Signing\\' => dirname(__DIR__) . '/src/',
    ];
    foreach ($prefixes as $prefix => $baseDirectory) {
        if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
            continue;
        }
        $relativeClass = substr($class, strlen($prefix));
        $file = $baseDirectory . str_replace('\\', '/', $relativeClass) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
