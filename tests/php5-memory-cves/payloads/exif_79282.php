<?php
// bug #79282: a 2-byte TIFF header plus a section allocated with itemlen+1.
var_dump(exif_read_data('data://image/jpeg;base64,/9jhAAlFeGlmAAAg'));
echo "MARKER=", 137 * 149, "\n";
