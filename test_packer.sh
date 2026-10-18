#!/bin/sh
# Smoke check for packer.py: build static non-PIE targets, pack them, and
# require identical stdout + exit code from original and packed binary.
# The test binary touches .bss far past the file image to catch placement
# bugs in the last-PT_LOAD extension.
set -e
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat > "$T/t.c" <<'EOF'
#include <stdio.h>
int bss_check[16384];
int main(void) {
    bss_check[16383] = 42;
    puts("hello packed world");
    return bss_check[16383] - 10; /* distinctive exit code 32 */
}
EOF

check() { # check <target>
    bin=$1
    python3 "$here/packer.py" "$bin" > /dev/null
    e1=0; "$bin" > "$T/orig.out" || e1=$?
    e2=0; "$bin.packed" > "$T/packed.out" || e2=$?
    cmp "$T/orig.out" "$T/packed.out"
    [ "$e1" = "$e2" ] || { echo "FAIL $bin: exit $e1 vs $e2"; exit 1; }
    echo "OK  $bin (exit $e1)"
}

gcc -static -no-pie "$T/t.c" -o "$T/t64"
check "$T/t64"

if gcc -m32 -static -no-pie "$T/t.c" -o "$T/t32" 2>/dev/null; then
    check "$T/t32"
else
    echo "SKIP 32-bit: gcc multilib not available"
fi

echo "all checks passed"