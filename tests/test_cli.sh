#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
for args in '--count 1x' '--window -1' '--window 0' '--service-us 1x' '--count 1 extra'; do
    set +e
    ./xfrm-bench $args >/dev/null 2>&1
    status=$?
    set -e
    test "$status" -eq 2
done
echo 'CLI validation passed'
