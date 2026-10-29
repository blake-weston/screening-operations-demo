<?php

declare(strict_types=1);

/**
 * Resolve a database-derived media filename without allowing the resulting
 * path to escape the selected media directory.
 */
function resolve_protected_media_path(string $baseDirectory, mixed $filename): ?string
{
    if (
        !is_string($filename)
        || $filename === ''
        || $filename === '.'
        || $filename === '..'
        || str_contains($filename, '/')
        || str_contains($filename, '\\')
        || basename($filename) !== $filename
    ) {
        return null;
    }

    $canonicalBase = realpath($baseDirectory);
    if ($canonicalBase === false || !is_dir($canonicalBase)) {
        return null;
    }

    $candidate = realpath($canonicalBase . DIRECTORY_SEPARATOR . $filename);
    if ($candidate === false) {
        return null;
    }

    $basePrefix = rtrim($canonicalBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (!str_starts_with($candidate, $basePrefix)) {
        return null;
    }

    if (!is_file($candidate) || !is_readable($candidate)) {
        return null;
    }

    return $candidate;
}
