/*
 * Harmless native admission probe for the U2 watchdog signing route.
 *
 * This program writes one fixed line to stdout and exits. It never loads
 * IOKit, opens a USB controller, changes a file, starts a service, or asks
 * for network/USB access. Its separate signing test can establish whether
 * a rootless native executable with the intended minimal entitlements can
 * reach main; it does not establish controller-write authorization.
 */
#include <unistd.h>

int main(void) {
    static const char message[] = "U2_NATIVE_ADMISSION alive\n";
    return write(STDOUT_FILENO, message, sizeof(message) - 1) ==
                   (ssize_t)(sizeof(message) - 1)
               ? 0
               : 1;
}
