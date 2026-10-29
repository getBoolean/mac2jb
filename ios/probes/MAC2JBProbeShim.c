#include "MAC2JBProbeShim.h"

#include <dlfcn.h>
#include <string.h>

typedef const void *MAC2JBControllerRef;
typedef const void *MAC2JBDescriptionRef;
typedef IOReturn (*ControllerCreateFunction)(CFAllocatorRef, MAC2JBControllerRef *);
typedef CFTypeID (*TypeIDFunction)(void);
typedef MAC2JBDescriptionRef (*DescriptionCreateFunction)(CFAllocatorRef, MAC2JBControllerRef);
typedef CFTypeRef (*TaskCreateFunction)(CFAllocatorRef);
typedef CFTypeRef (*EntitlementCopyFunction)(CFTypeRef, CFStringRef, CFErrorRef *);

static void *iokit_handle(void) {
    static void *handle;
    static bool attempted;
    if (!attempted) {
        attempted = true;
        handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    }
    return handle;
}

bool MAC2JBSymbolAvailable(const char *name) {
    void *handle = iokit_handle();
    return handle && name && dlsym(handle, name) != NULL;
}

void MAC2JBProbePrivateAPI(MAC2JBPrivateAPIReadback *result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    result->controllerCreateStatus = (int32_t)kIOReturnUnsupported;

    void *handle = iokit_handle();
    if (!handle) return;

    ControllerCreateFunction createController = (ControllerCreateFunction)dlsym(handle, "IOUSBDeviceControllerCreate");
    TypeIDFunction controllerTypeID = (TypeIDFunction)dlsym(handle, "IOUSBDeviceControllerGetTypeID");
    DescriptionCreateFunction createDescription = (DescriptionCreateFunction)dlsym(handle, "IOUSBDeviceDescriptionCreateFromController");
    TypeIDFunction descriptionTypeID = (TypeIDFunction)dlsym(handle, "IOUSBDeviceDescriptionGetTypeID");

    result->controllerCreateAvailable = createController != NULL;
    result->controllerTypeIDAvailable = controllerTypeID != NULL;
    result->descriptionCreateAvailable = createDescription != NULL;
    result->descriptionTypeIDAvailable = descriptionTypeID != NULL;
    if (!createController) return;

    MAC2JBControllerRef controller = NULL;
    result->controllerCreateStatus = (int32_t)createController(kCFAllocatorDefault, &controller);
    if (result->controllerCreateStatus != kIOReturnSuccess || !controller) return;
    result->controllerCreated = true;
    if (controllerTypeID) result->controllerTypeMatches = CFGetTypeID(controller) == controllerTypeID();

    if (createDescription) {
        MAC2JBDescriptionRef description = createDescription(kCFAllocatorDefault, controller);
        if (description) {
            result->descriptionCreated = true;
            if (descriptionTypeID) result->descriptionTypeMatches = CFGetTypeID(description) == descriptionTypeID();
            CFRelease(description);
        }
    }
    CFRelease(controller);
}

static CFTypeRef copy_entitlement_value(const char *name) {
    if (!name) return NULL;
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    if (!security) return NULL;
    TaskCreateFunction createTask = (TaskCreateFunction)dlsym(security, "SecTaskCreateFromSelf");
    EntitlementCopyFunction copyEntitlement = (EntitlementCopyFunction)dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!createTask || !copyEntitlement) return NULL;

    CFStringRef entitlementName = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingUTF8);
    CFTypeRef task = createTask(kCFAllocatorDefault);
    if (!entitlementName || !task) {
        if (entitlementName) CFRelease(entitlementName);
        if (task) CFRelease(task);
        return NULL;
    }

    CFErrorRef error = NULL;
    CFTypeRef value = copyEntitlement(task, entitlementName, &error);
    if (error) CFRelease(error);
    CFRelease(task);
    CFRelease(entitlementName);
    return value;
}

bool MAC2JBHasEntitlement(const char *name) {
    CFTypeRef value = copy_entitlement_value(name);
    bool present = value != NULL;
    if (value && CFGetTypeID(value) == CFBooleanGetTypeID()) present = CFBooleanGetValue((CFBooleanRef)value);
    if (value) CFRelease(value);
    return present;
}

bool MAC2JBEntitlementContainsString(const char *name, const char *expected) {
    if (!expected) return false;
    CFTypeRef value = copy_entitlement_value(name);
    if (!value) return false;

    CFStringRef expectedValue = CFStringCreateWithCString(kCFAllocatorDefault, expected, kCFStringEncodingUTF8);
    bool contains = false;
    if (expectedValue && CFGetTypeID(value) == CFStringGetTypeID()) {
        contains = CFEqual(value, expectedValue);
    } else if (expectedValue && CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFArrayRef values = (CFArrayRef)value;
        CFIndex count = CFArrayGetCount(values);
        for (CFIndex index = 0; index < count && !contains; index++) {
            CFTypeRef candidate = CFArrayGetValueAtIndex(values, index);
            contains = candidate && CFGetTypeID(candidate) == CFStringGetTypeID() && CFEqual(candidate, expectedValue);
        }
    }

    if (expectedValue) CFRelease(expectedValue);
    CFRelease(value);
    return contains;
}

const char *MAC2JBIOReturnCategory(int32_t value) {
    switch ((IOReturn)value) {
        case kIOReturnSuccess: return "success";
        case kIOReturnNotPrivileged:
        case kIOReturnNotPermitted: return "entitlement-or-privilege-denied";
        case kIOReturnUnsupported: return "unsupported-operation-or-user-client-type";
        case kIOReturnNoDevice:
        case kIOReturnNotAttached: return "controller-role-or-service-unavailable";
        case kIOReturnNotOpen: return "user-client-not-open";
        case kIOReturnExclusiveAccess: return "user-client-already-open";
        case kIOReturnBadArgument: return "abi-or-argument-mismatch";
        default: return "iokit-error";
    }
}
