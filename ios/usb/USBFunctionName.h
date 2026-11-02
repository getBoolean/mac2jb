#ifndef MAC2JB_USB_FUNCTION_NAME_H
#define MAC2JB_USB_FUNCTION_NAME_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ . The broker checks a name before it
// publishes it and the interface matcher checks before it looks for it, so the
// two have to agree: a name one accepts and the other rejects publishes a
// function that can never be found, which on the device is indistinguishable
// from the kernel never materializing it. Header-only and inline, so neither
// shim gains a link dependency on the other.
#define MAC2JB_USB_FUNCTION_NAME_MAX 32

static inline bool mac2jb_usb_function_name_character(char c, bool first) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
        return true;
    return !first && (c == '_' || c == '.' || c == '-');
}

static inline bool mac2jb_usb_function_name_is_legal(const char *name) {
    if (!name || !name[0]) return false;
    size_t length = strnlen(name, MAC2JB_USB_FUNCTION_NAME_MAX + 1);
    if (length > MAC2JB_USB_FUNCTION_NAME_MAX) return false;
    for (size_t index = 0; index < length; index++)
        if (!mac2jb_usb_function_name_character(name[index], index == 0)) return false;
    return true;
}

#endif
