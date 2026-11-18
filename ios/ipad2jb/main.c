// ipad2jb command line:  sudo ipad2jb [TEXT...]
// TEXT defaults to "ipad2jb"; several words are joined with spaces. Letters,
// digits and spaces only. Needs root and the entitlements in ipad2jb.entitlements.

#include "iokit.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define STOCK_PATH "/var/jb/var/lib/ipad2jb/stock-description.plist"

static volatile sig_atomic_t interrupted = 0;
static void on_signal(int signal_number) { (void)signal_number; interrupted = 1; }

static void say(const char *message) { printf("ipad2jb: %s\n", message); fflush(stdout); }
static void sleep_ms(unsigned milliseconds) { usleep(milliseconds * 1000); }

static bool join_arguments(int argc, char **argv, char *text, size_t capacity) {
    if (argc < 2) { snprintf(text, capacity, "ipad2jb"); return true; }
    text[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strlen(text) + strlen(argv[i]) + 2 > capacity) return false;
        if (i > 1) strcat(text, " ");
        strcat(text, argv[i]);
    }
    return true;
}

int main(int argc, char **argv) {
    char text[IPAD2JB_MAX_TEXT + 1];
    if (!join_arguments(argc, argv, text, sizeof(text)) || !ipad2jb_text_is_typable(text)) {
        fprintf(stderr, "ipad2jb: text must be 1-%d letters, digits and spaces\n", IPAD2JB_MAX_TEXT);
        return 1;
    }
    if (getuid() != 0) { fprintf(stderr, "ipad2jb: run as root: sudo ipad2jb\n"); return 1; }

    // Interrupts end the typing early but never skip the restore. A closed
    // terminal or SSH session must not kill the process with SIGPIPE either.
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    signal(SIGPIPE, SIG_IGN);

    ipad2jb_env env = { .stock_path = STOCK_PATH, .sleep_ms = sleep_ms, .say = say,
                        .interrupted = &interrupted };
    if (!ipad2jb_iokit_usb(&env.usb)) { say("USB device controller unavailable"); return 1; }
    ipad2jb_iokit_keyboard(&env.keyboard);

    ipad2jb_outcome outcome = ipad2jb_run(&env, text);
    if (outcome.typing == IPAD2JB_TYPED) printf("ipad2jb: typed \"%s\"\n", text);
    bool restored = outcome.restore == IPAD2JB_RESTORED || outcome.restore == IPAD2JB_RESTORED_NO_HOST;
    return outcome.typing == IPAD2JB_TYPED && restored ? 0 : 1;
}
