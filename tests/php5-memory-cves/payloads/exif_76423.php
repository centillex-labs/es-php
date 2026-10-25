<?php
// bug #76423: Thumbnail.offset + size overflows the ExifLength check.
exif_read_data(__DIR__ . '/bug76423.jpg', 0, true, true);
echo "MARKER=", 137 * 149, "\n";
