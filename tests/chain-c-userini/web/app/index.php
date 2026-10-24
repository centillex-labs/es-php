<?php
/* Chain C writer endpoint.
 * .user.ini in this directory sets session.serialize_handler = php_serialize,
 * so the session file is written as one serialized blob with no key delimiter.
 * The uploaded filename (attacker controlled) lands inside that blob. */
header('Content-Type: text/plain');
session_start();
echo "handler=" . ini_get('session.serialize_handler') . "\n";
echo "sid=" . session_id() . "\n";
echo "keys=" . implode(',', array_keys($_SESSION)) . "\n";
