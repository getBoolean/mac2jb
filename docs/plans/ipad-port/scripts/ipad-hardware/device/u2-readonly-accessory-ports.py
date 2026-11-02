#!/var/jb/usr/bin/python3
"""Bounded read-only census of IOAccessoryPort services anywhere in the registry.

Effect: matches class IOAccessoryPort, and for each instance prints its class,
three levels of provider classes, and allowlisted scalar properties (numbers
and booleans only; property names, no strings, IDs, or nested values).
No writes, user clients, or commands.
"""

import ctypes
import re

CLASS = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,99}\Z")
KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
UTF8 = 0x08000100


def main():
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    io.IOServiceMatching.argtypes = (ctypes.c_char_p,)
    io.IOServiceMatching.restype = ctypes.c_void_p
    io.IOServiceGetMatchingServices.argtypes = (ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    io.IOIteratorNext.argtypes = (ctypes.c_uint32,)
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = (ctypes.c_uint32,)
    io.IOObjectGetClass.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
    io.IORegistryEntryGetParentEntry.argtypes = (ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32))
    io.IORegistryEntryCreateCFProperties.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_uint32)
    cf.CFDictionaryGetCount.argtypes = (ctypes.c_void_p,)
    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetKeysAndValues.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    cf.CFGetTypeID.argtypes = (ctypes.c_void_p,)
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetValue.argtypes = (ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p)
    cf.CFBooleanGetValue.argtypes = (ctypes.c_void_p,)
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32)
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFRelease.argtypes = (ctypes.c_void_p,)

    def cls(entry):
        b = ctypes.create_string_buffer(128)
        io.IOObjectGetClass(entry, b)
        n = b.value.decode("ascii", "replace")
        return n if CLASS.fullmatch(n) else "invalid"

    count = 0
    for match in (b"IOAccessoryManager", b"IOAccessoryPort", b"IOAccessoryPortUSB",
                  b"IOAccessoryPortUserClient", b"IOAccessoryUSBConnectInterface"):
      it = ctypes.c_uint32()
      if io.IOServiceGetMatchingServices(0, io.IOServiceMatching(match), ctypes.byref(it)) != 0:
        continue
      while count < 32:
          s = io.IOIteratorNext(it.value)
          if not s:
              break
          count += 1
          chain, e = [], s
          for _ in range(3):
              p = ctypes.c_uint32()
              if io.IORegistryEntryGetParentEntry(e, b"IOService", ctypes.byref(p)) != 0:
                  break
              chain.append(cls(p.value))
              if e != s:
                  io.IOObjectRelease(e)
              e = p.value
          if e != s:
              io.IOObjectRelease(e)
          props = []
          d = ctypes.c_void_p()
          if io.IORegistryEntryCreateCFProperties(s, ctypes.byref(d), None, 0) == 0 and d.value:
              n = min(cf.CFDictionaryGetCount(d), 96)
              keys = (ctypes.c_void_p * n)(); vals = (ctypes.c_void_p * n)()
              cf.CFDictionaryGetKeysAndValues(d, keys, vals)
              for k, v in zip(keys, vals):
                  kb = ctypes.create_string_buffer(80)
                  if not cf.CFStringGetCString(k, kb, 80, UTF8):
                      continue
                  key = kb.value.decode("ascii", "replace")
                  if not KEY.fullmatch(key):
                      continue
                  t = cf.CFGetTypeID(v)
                  if t == cf.CFBooleanGetTypeID():
                      props.append("%s=%s" % (key, "yes" if cf.CFBooleanGetValue(v) else "no"))
                  elif t == cf.CFNumberGetTypeID():
                      x = ctypes.c_int64()
                      if cf.CFNumberGetValue(v, 4, ctypes.byref(x)) and -1 <= x.value <= 65535:
                          props.append("%s=%d" % (key, x.value))
              cf.CFRelease(d)
          print("U2_APORT match=%s class=%s parents=%s %s" % (match.decode(), cls(s), ">".join(chain), " ".join(sorted(props))))
          io.IOObjectRelease(s)
      io.IOObjectRelease(it.value)
    print("U2_APORT count=%d done" % count)


if __name__ == "__main__":
    main()
