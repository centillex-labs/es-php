<?php
// bug #78878: high bytes are not decimal digits; the old isdigit() loop walked
// past the number and let the sign field be consumed, underflowing the buffer.
echo @bcmul("\xB26483605105519922841849335928742092", bcpowmod(2, 65535, -4e-4)), "\n";
echo "MARKER=", 137 * 149, "\n";
