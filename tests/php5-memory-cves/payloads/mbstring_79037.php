<?php
// bug #79037: CP950 trail bytes below 0x40 reach the PUA table lookup.
var_dump(mb_convert_encoding("\x81\x3a", "UTF-8", "CP950"));
echo "MARKER=", 137 * 149, "\n";
