#!/usr/bin/env bash
# AESOP showcase — a guided tour you can actually run.
# Each step is isolated; a failure in one won't stop the tour.
set -u
AESOP="python3 -m aesop"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

step() { printf '\n\033[1;33m» %s\033[0m\n\033[2m$ %s\033[0m\n' "$1" "$2"; }
run()  { eval "$2" || echo "  (step skipped or failed)"; }

step "Who are we?" "$AESOP version"
run "" "$AESOP version"

step "Break a Caesar cipher with no key" "$AESOP caesar 'Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj'"
run "" "$AESOP caesar 'Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj'"

step "Peel a nested encoding automatically" "echo 'ZmxhZ3tuZXN0ZWR9' | $AESOP magic"
run "" "echo 'ZmxhZ3tuZXN0ZWR9' | $AESOP magic"

step "Break a Vigenere cipher (auto key length + key)" \
     "$AESOP vigenere 'Lxfopv ef rnhr'"
run "" "$AESOP vigenere 'Lxfopv ef rnhr'"

step "Break repeating-key XOR" \
     "python3 -c \"import sys;d=bytes(a^b for a,b in zip(b'Attack at dawn, hold the line until dusk!',(b'FOX'*20)));sys.stdout.buffer.write(d)\" | $AESOP xor --repeating"
run "" "python3 -c \"import sys;d=bytes(a^b for a,b in zip(b'Attack at dawn, hold the line until dusk!',(b'FOX'*20)));sys.stdout.buffer.write(d)\" | $AESOP xor --repeating"

step "Identify an unknown blob" "$AESOP identify 'SGVsbG8gV29ybGQh'"
run "" "$AESOP identify 'SGVsbG8gV29ybGQh'"

step "Frequency analysis & Index of Coincidence" \
     "$AESOP freq 'Lxfopvefrnhr lxfopvefrnhr lxfopvefrnhr'"
run "" "$AESOP freq 'Lxfopvefrnhr lxfopvefrnhr lxfopvefrnhr'"

step "Identify a hash" "$AESOP hash-id 5f4dcc3b5aa765d61d8327deb882cf99"
run "" "$AESOP hash-id 5f4dcc3b5aa765d61d8327deb882cf99"

step "Read the manual for any technique" "$AESOP manual vigenere"
echo "  (try:  $AESOP manual vigenere )"

printf '\n\033[1;32mTour complete. Explore more with: %s list\033[0m\n' "$AESOP"
