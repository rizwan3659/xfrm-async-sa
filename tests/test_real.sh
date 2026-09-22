#!/bin/sh
# SPDX-License-Identifier: MIT
# Run only inside a disposable network namespace: sudo unshare -n sh tests/test_real.sh
set -eu
./xfrm-bench --real --count 16 --window 8
test -z "$(ip xfrm state list)"
# An EEXIST failure must not cause cleanup to delete someone else's SA.
ip xfrm state add src 192.0.2.1 dst 198.18.0.0 proto esp spi 0x1000 \
    mode transport aead 'rfc4106(gcm(aes))' \
    0x000102030405060708090a0b0c0d0e0f10111213 128
set +e
./xfrm-bench --real --count 1 --window 1
status=$?
set -e
test "$status" -eq 1
ip xfrm state get dst 198.18.0.0 proto esp spi 0x1000 >/dev/null
ip xfrm state delete dst 198.18.0.0 proto esp spi 0x1000
echo 'real-kernel install, cleanup and EEXIST preservation passed'
