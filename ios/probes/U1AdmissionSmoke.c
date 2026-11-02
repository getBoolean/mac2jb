// Minimal iPad process-admission check for the entitlement-free U1 row.
//
// This code writes one fixed marker to standard output and exits. It does not
// load IOKit, inspect the USB bus, create a user client, open a file, or change
// any iPad setting. A successful run would show that a plain C executable can
// reach main without private entitlements; it would not itself clear U1 R2.

#include <unistd.h>

int main(void) {
    static const char marker[] = "U1_ADMISSION_SMOKE reached-main\n";
    return write(STDOUT_FILENO, marker, sizeof(marker) - 1) ==
                   (ssize_t)(sizeof(marker) - 1)
               ? 0
               : 1;
}
