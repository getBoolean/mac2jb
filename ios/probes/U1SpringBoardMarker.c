// Observe whether SpringBoard starts an ordinary TrollStore app at all.
//
// The executable touches no IOKit, USB, SSH, trust, or system configuration.
// On a no-argument launch it creates one fixed receipt in its own app data
// container's tmp directory, then exits. The receipt is tracked for cleanup.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char receipt_name[] = ".mac2jb-u1-springboard-marker";
static const char receipt[] = "MAC2JB_U1_SPRINGBOARD_REACHED_MAIN v1\n";

int main(int argc, char *argv[]) {
    (void)argv;
    if (argc != 1) return 64;
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || strlen(tmp) >= PATH_MAX) return 65;
    const char *normal = "/var/mobile/Containers/Data/Application/";
    const char *private = "/private/var/mobile/Containers/Data/Application/";
    if (strncmp(tmp, normal, strlen(normal)) != 0 &&
        strncmp(tmp, private, strlen(private)) != 0) return 66;
    if (strstr(tmp, "/../") != NULL || strstr(tmp, "/./") != NULL) return 66;
    size_t len = strlen(tmp);
    if (len >= 4 && tmp[len - 1] == '/') len--;
    if (len < 4 || strncmp(tmp + len - 4, "/tmp", 4) != 0) return 66;
    int dir = open(tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 67;
    struct stat info;
    if (fstat(dir, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid()) {
        close(dir);
        return 68;
    }
    int fd = openat(dir, receipt_name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        int saved_errno = errno;
        close(dir);
        return saved_errno == EEXIST ? 69 : 70;
    }
    ssize_t count = write(fd, receipt, sizeof(receipt) - 1);
    int sync_result = fsync(fd);
    int close_result = close(fd);
    close(dir);
    return count == (ssize_t)(sizeof(receipt) - 1) &&
                   sync_result == 0 && close_result == 0 ? 0 : 71;
}
