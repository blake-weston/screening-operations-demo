<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

flash('error', 'This demo has been repointed to the CT scan dashboard.');
redirect('/index.php');
