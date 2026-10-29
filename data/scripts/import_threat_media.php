<?php

declare(strict_types=1);

require __DIR__ . '/../bootstrap.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Run this script via the PHP CLI inside the web container.\n");
    exit(1);
}

$manifestPath = $argv[1] ?? '/srv/threat_media/import/seed_manifest.csv';
$manifestRealPath = realpath($manifestPath);

if ($manifestRealPath === false || !is_file($manifestRealPath)) {
    fwrite(STDERR, "Manifest not found: {$manifestPath}\n");
    exit(1);
}

$originalsDir = '/srv/threat_media/originals';
$thumbnailsDir = '/srv/threat_media/thumbnails';
$importDir = '/srv/threat_media/import/source';

if (!is_dir($originalsDir) || !is_dir($thumbnailsDir) || !is_dir($importDir)) {
    fwrite(STDERR, "Mounted media directories are missing.\n");
    exit(1);
}

$handle = fopen($manifestRealPath, 'rb');
if ($handle === false) {
    fwrite(STDERR, "Unable to open manifest.\n");
    exit(1);
}

$header = fgetcsv($handle);
if ($header === false) {
    fwrite(STDERR, "Manifest is empty.\n");
    exit(1);
}

$expectedHeader = ['event_id', 'threat_category', 'source_filename'];
if ($header !== $expectedHeader) {
    fwrite(STDERR, "Manifest header must be: " . implode(',', $expectedHeader) . "\n");
    exit(1);
}

$selectStatement = db()->prepare('SELECT id, threat_category FROM scan_events WHERE id = :id LIMIT 1');
$updateStatement = db()->prepare(
    'UPDATE scan_events
     SET sixray_image_filename = :image_filename,
         thumbnail_filename = :thumbnail_filename
     WHERE id = :id'
);

while (($row = fgetcsv($handle)) !== false) {
    if (count($row) !== 3) {
        fwrite(STDERR, "Skipping malformed row.\n");
        continue;
    }

    [$eventId, $threatCategory, $sourceFilename] = $row;
    $eventId = (int) $eventId;
    $threatCategory = trim($threatCategory);
    $sourceFilename = trim($sourceFilename);
    $sourcePath = $importDir . '/' . $sourceFilename;
    $sourceRealPath = realpath($sourcePath);

    if (
        $eventId <= 0
        || $sourceFilename === ''
        || basename($sourceFilename) !== $sourceFilename
        || $sourceRealPath === false
        || !str_starts_with($sourceRealPath, realpath($importDir) . DIRECTORY_SEPARATOR)
        || !is_file($sourceRealPath)
    ) {
        fwrite(STDERR, "Skipping invalid row for event {$eventId}.\n");
        continue;
    }

    $selectStatement->execute(['id' => $eventId]);
    $event = $selectStatement->fetch();

    if (!$event) {
        fwrite(STDERR, "Event {$eventId} not found.\n");
        continue;
    }

    if ($event['threat_category'] !== $threatCategory) {
        fwrite(STDERR, "Threat category mismatch for event {$eventId}: expected {$event['threat_category']}, got {$threatCategory}.\n");
        continue;
    }

    $extension = strtolower(pathinfo($sourceRealPath, PATHINFO_EXTENSION));
    if (!in_array($extension, ['jpg', 'jpeg', 'png'], true)) {
        fwrite(STDERR, "Unsupported image type for event {$eventId}.\n");
        continue;
    }

    $normalizedExtension = $extension === 'jpeg' ? 'jpg' : $extension;
    $imageFilename = sprintf('event-%02d-%s.%s', $eventId, $threatCategory, $normalizedExtension);
    $thumbnailFilename = sprintf('event-%02d-%s-thumb.jpg', $eventId, $threatCategory);

    $imageDestination = $originalsDir . '/' . $imageFilename;
    $thumbnailDestination = $thumbnailsDir . '/' . $thumbnailFilename;

    if (!copy($sourceRealPath, $imageDestination)) {
        fwrite(STDERR, "Failed to copy original image for event {$eventId}.\n");
        continue;
    }

    chmod($imageDestination, 0640);

    if (!create_thumbnail($imageDestination, $thumbnailDestination, 220, 160)) {
        fwrite(STDERR, "Failed to create thumbnail for event {$eventId}.\n");
        continue;
    }

    chmod($thumbnailDestination, 0640);

    $updateStatement->execute([
        'id' => $eventId,
        'image_filename' => $imageFilename,
        'thumbnail_filename' => $thumbnailFilename,
    ]);

    fwrite(STDOUT, "Imported event {$eventId} image.\n");
}

fclose($handle);

function create_thumbnail(string $sourcePath, string $destinationPath, int $targetWidth, int $targetHeight): bool
{
    $imageInfo = getimagesize($sourcePath);
    if ($imageInfo === false) {
        return false;
    }

    [$sourceWidth, $sourceHeight, $sourceType] = $imageInfo;

    $sourceImage = match ($sourceType) {
        IMAGETYPE_JPEG => imagecreatefromjpeg($sourcePath),
        IMAGETYPE_PNG => imagecreatefrompng($sourcePath),
        default => false,
    };

    if ($sourceImage === false) {
        return false;
    }

    $ratio = min($targetWidth / $sourceWidth, $targetHeight / $sourceHeight);
    $newWidth = max(1, (int) floor($sourceWidth * $ratio));
    $newHeight = max(1, (int) floor($sourceHeight * $ratio));

    $thumbnail = imagecreatetruecolor($targetWidth, $targetHeight);
    if ($thumbnail === false) {
        imagedestroy($sourceImage);
        return false;
    }

    $background = imagecolorallocate($thumbnail, 245, 241, 234);
    imagefill($thumbnail, 0, 0, $background);

    $destinationX = (int) floor(($targetWidth - $newWidth) / 2);
    $destinationY = (int) floor(($targetHeight - $newHeight) / 2);

    imagecopyresampled(
        $thumbnail,
        $sourceImage,
        $destinationX,
        $destinationY,
        0,
        0,
        $newWidth,
        $newHeight,
        $sourceWidth,
        $sourceHeight
    );

    $result = imagejpeg($thumbnail, $destinationPath, 85);
    imagedestroy($sourceImage);
    imagedestroy($thumbnail);

    return $result;
}
