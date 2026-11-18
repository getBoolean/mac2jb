// The real ipad2jb device interfaces, backed by the iPad's USB device controller.
#ifndef IPAD2JB_IOKIT_H
#define IPAD2JB_IOKIT_H

#include "ipad2jb.h"

// Load the private controller API and fill `out`; false if unavailable.
bool ipad2jb_iokit_usb(ipad2jb_usb *out);
void ipad2jb_iokit_keyboard(ipad2jb_keyboard *out, unsigned poll_interval);

#endif
