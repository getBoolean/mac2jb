#!/var/jb/usr/bin/python3
"""Bounded read-only device lock/screen state.

Effect: calls MobileKeyBag MKBGetDeviceLockState(NULL) and reads the notify
state of com.apple.springboard.lockstate and com.apple.springboard.hasBlankedScreen
via notify_register_check/notify_get_state. Prints three integers. No writes,
posts, or UI actions.
"""

import ctypes


def notify_state(libc, name):
    token = ctypes.c_int()
    if libc.notify_register_check(name, ctypes.byref(token)) != 0:
        return "unknown"
    state = ctypes.c_uint64()
    status = libc.notify_get_state(token.value, ctypes.byref(state))
    libc.notify_cancel(token.value)
    return str(state.value) if status == 0 else "unknown"


def main():
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    libc.notify_register_check.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_int))
    libc.notify_get_state.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint64))
    libc.notify_cancel.argtypes = (ctypes.c_int,)
    try:
        mkb = ctypes.CDLL("/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag")
        mkb.MKBGetDeviceLockState.argtypes = (ctypes.c_void_p,)
        mkb.MKBGetDeviceLockState.restype = ctypes.c_int
        keybag = str(mkb.MKBGetDeviceLockState(None))
    except (OSError, AttributeError):
        keybag = "unknown"
    print("U2_LOCK keybag=%s springboard-lockstate=%s blanked=%s" % (
        keybag, notify_state(libc, b"com.apple.springboard.lockstate"),
        notify_state(libc, b"com.apple.springboard.hasBlankedScreen")))


if __name__ == "__main__":
    main()
