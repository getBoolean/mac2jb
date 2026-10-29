#ifndef MAC2JB_PROBE_SHIM_H
#define MAC2JB_PROBE_SHIM_H

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool controllerCreateAvailable;
    bool controllerTypeIDAvailable;
    bool descriptionCreateAvailable;
    bool descriptionTypeIDAvailable;
    bool controllerCreated;
    bool descriptionCreated;
    bool controllerTypeMatches;
    bool descriptionTypeMatches;
    int32_t controllerCreateStatus;
} MAC2JBPrivateAPIReadback;

bool MAC2JBSymbolAvailable(const char *name);
void MAC2JBProbePrivateAPI(MAC2JBPrivateAPIReadback *result);
bool MAC2JBHasEntitlement(const char *name);
bool MAC2JBEntitlementContainsString(const char *name, const char *expected);
const char *MAC2JBIOReturnCategory(int32_t value);

#endif
