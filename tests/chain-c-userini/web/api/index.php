<?php
/* Chain C reader endpoint.
 * .user.ini in this directory sets session.serialize_handler = php, which
 * expects "key|serialized_value". Given a session file written by the
 * php_serialize handler that happens to contain a '|', the php handler splits
 * at the delimiter and unserializes whatever follows -- an object injection.
 *
 * The class must be declared before session_start(), otherwise the payload
 * degrades to __PHP_Incomplete_Class and no destructor runs. */
header('Content-Type: text/plain');

class MismatchProbe {
    public function __destruct() {
        @file_put_contents('/data/injected', "DESTRUCT_FIRED\n");
    }
}

session_start();
echo "handler=" . ini_get('session.serialize_handler') . "\n";
echo "session=" . serialize($_SESSION) . "\n";
