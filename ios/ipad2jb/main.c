// ipad2jb command line:  sudo ipad2jb [TEXT...]
// TEXT defaults to "ipad2jb"; --file PATH reads ASCII text from a separate file.
// Needs root and the entitlements in ipad2jb.entitlements.

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

static bool read_file(const char *path, char *text) {
    FILE *file = fopen(path, "rb");
    if (!file) { perror(path); return false; }
    size_t count = fread(text, 1, IPAD2JB_MAX_TEXT + 1, file);
    bool ok = !ferror(file) && count > 0 && count <= IPAD2JB_MAX_TEXT &&
              memchr(text, 0, count) == NULL;
    fclose(file);
    if (!ok) return false;
    // Normalize Windows and classic Mac line endings to one Enter per line.
    size_t out = 0;
    for (size_t i = 0; i < count; i++) {
        if (text[i] == '\r') {
            text[out++] = '\n';
            if (i + 1 < count && text[i + 1] == '\n') i++;
        } else text[out++] = text[i];
    }
    text[out] = 0;
    return true;
}

int main(int argc, char **argv) {
    static char text[IPAD2JB_MAX_TEXT + 2];
    bool caps_lock = false, fast = false, turbo = false;
    while (argc > 1) {
        if (strcmp(argv[1], "--caps-lock") == 0) caps_lock = true;
        else if (strcmp(argv[1], "--fast") == 0) fast = true;
        else if (strcmp(argv[1], "--turbo") == 0) { fast = true; turbo = true; }
        else break;
        argc--; argv++;
    }
    bool file_mode = argc > 1 && strcmp(argv[1], "--file") == 0;
    bool loaded = file_mode ? argc == 3 && read_file(argv[2], text)
                            : join_arguments(argc, argv, text, sizeof(text));
    if (!loaded || !ipad2jb_text_is_typable(text)) {
        fprintf(stderr, "ipad2jb: use [--fast|--turbo] [--caps-lock] TEXT or --file PATH; expected 1-%d printable ASCII bytes and newlines\n", IPAD2JB_MAX_TEXT);
        return 1;
    }
    // Manual case compensation; the host/editor lock state is not detected.
    if (caps_lock) {
        for (char *c = text; *c; c++) {
            if (*c >= 'a' && *c <= 'z') *c = (char)(*c - 'a' + 'A');
            else if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
        }
    }
    if (getuid() != 0) { fprintf(stderr, "ipad2jb: run as root: sudo ipad2jb\n"); return 1; }

    // Interrupts end the typing early but never skip the restore. A closed
    // terminal or SSH session must not kill the process with SIGPIPE either.
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    signal(SIGPIPE, SIG_IGN);

    ipad2jb_env env = {
        .turbo_typing = turbo, .fast_typing = fast, .clear_autoindent = file_mode,
        .stock_path = STOCK_PATH, .sleep_ms = sleep_ms, .say = say,
        .interrupted = &interrupted,
    };
    if (!ipad2jb_iokit_usb(&env.usb)) { say("USB device controller unavailable"); return 1; }
    ipad2jb_iokit_keyboard(&env.keyboard, turbo ? 4 : fast ? 6 : 10);

    ipad2jb_outcome outcome = ipad2jb_run(&env, text);
    if (outcome.typing == IPAD2JB_TYPED) printf("ipad2jb: typed %zu bytes\n", strlen(text));
    bool restored = outcome.restore == IPAD2JB_RESTORED || outcome.restore == IPAD2JB_RESTORED_NO_HOST;
    return outcome.typing == IPAD2JB_TYPED && restored ? 0 : 1;
}
