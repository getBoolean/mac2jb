// Mac-only tests for the pure additive-description helper in the USB restore
// shim. No IOKit controller is created and nothing is published: the helper
// works on plist bytes only, so the exact code the broker runs on the device
// can be proved here. Run from the additive-publication python test.
#include "../usb/USBRestoreControllerShim.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIGURATION_COUNT 9
// The host-selected configuration is read from the controller on the device;
// here it is just the configuration the tests target.
#define TARGET_CONFIGURATION 5

static int failures = 0;

static void check(bool condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "FAIL %s\n", what);
        failures++;
    }
}

static CFMutableDictionaryRef make_configuration(int index, const char *const *interfaces) {
    CFMutableArrayRef names = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                   &kCFTypeArrayCallBacks);
    for (const char *const *name = interfaces; name && *name; name++) {
        CFStringRef value = CFStringCreateWithCString(kCFAllocatorDefault, *name,
                                                      kCFStringEncodingUTF8);
        CFArrayAppendValue(names, value);
        CFRelease(value);
    }
    CFMutableDictionaryRef configuration = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFStringRef description = CFStringCreateWithFormat(
        kCFAllocatorDefault, NULL, CFSTR("configuration-%d"), index);
    CFDictionarySetValue(configuration, CFSTR("Description"), description);
    CFDictionarySetValue(configuration, CFSTR("Interfaces"), names);
    CFRelease(description);
    CFRelease(names);
    return configuration;
}

static void set_number(CFMutableDictionaryRef dictionary, CFStringRef key, int value) {
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
    CFDictionarySetValue(dictionary, key, number);
    CFRelease(number);
}

// A synthetic stand-in for the live device description: device-level scalars
// plus an array of configurations, each holding an array of function names.
static CFDictionaryRef make_description(void) {
    CFMutableDictionaryRef info = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    set_number(info, CFSTR("vendorID"), 1452);
    set_number(info, CFSTR("productID"), 4779);
    set_number(info, CFSTR("deviceClass"), 0);
    set_number(info, CFSTR("deviceSubClass"), 0);
    set_number(info, CFSTR("deviceProtocol"), 0);
    set_number(info, CFSTR("BcdUSBVersion"), 768);
    set_number(info, CFSTR("MPS0"), 9);
    set_number(info, CFSTR("MaxPower"), 112);
    CFDictionarySetValue(info, CFSTR("productString"), CFSTR("synthetic"));
    CFDictionarySetValue(info, CFSTR("serialNumber"), CFSTR("synthetic-serial"));
    CFMutableArrayRef configurations = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                                            &kCFTypeArrayCallBacks);
    static const char *const first[] = {"Valeria", NULL};
    static const char *const selected[] = {"PTP", "USBAudio2StreamOUT", "AppleUSBMux", NULL};
    for (int index = 1; index <= CONFIGURATION_COUNT; index++) {
        const char *const *interfaces = NULL;
        if (index == 1) interfaces = first;
        if (index == TARGET_CONFIGURATION) interfaces = selected;
        CFMutableDictionaryRef configuration = make_configuration(index, interfaces);
        CFArrayAppendValue(configurations, configuration);
        CFRelease(configuration);
    }
    CFDictionarySetValue(info, CFSTR("ConfigurationDescriptors"), configurations);
    CFRelease(configurations);
    return info;
}

static CFDataRef encode(CFDictionaryRef info) {
    return CFPropertyListCreateData(kCFAllocatorDefault, info,
                                    kCFPropertyListBinaryFormat_v1_0, 0, NULL);
}

static CFDictionaryRef decode(const uint8_t *bytes, size_t length) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)length);
    if (!data) return NULL;
    CFPropertyListRef plist = CFPropertyListCreateWithData(
        kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data);
    if (plist && CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        CFRelease(plist);
        return NULL;
    }
    return (CFDictionaryRef)plist;
}

static MAC2JBUSBResult append_to(CFDataRef input, const char *name,
                                 int32_t configurationNumber, CFDictionaryRef *out) {
    uint8_t *bytes = NULL;
    size_t length = 0;
    MAC2JBUSBResult result = MAC2JBUSBAppendFunctionToDescriptionData(
        CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), name,
        configurationNumber, &bytes, &length);
    if (out) *out = NULL;
    if (result == MAC2JBUSBSuccess && out) *out = decode(bytes, length);
    if (result != MAC2JBUSBSuccess) check(bytes == NULL && length == 0,
                                         "rejected append returned no buffer");
    MAC2JBUSBFreeCapturedDescription(bytes);
    return result;
}

static MAC2JBUSBResult remove_from(CFDataRef input, const char *name,
                                   int32_t configurationNumber, CFDataRef *out) {
    uint8_t *bytes = NULL;
    size_t length = 0;
    MAC2JBUSBResult result = MAC2JBUSBRemoveFunctionFromDescriptionData(
        CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), name,
        configurationNumber, &bytes, &length);
    if (out) *out = NULL;
    if (result == MAC2JBUSBSuccess && out && bytes)
        *out = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)length);
    if (result != MAC2JBUSBSuccess) check(bytes == NULL && length == 0,
                                         "rejected removal returned no buffer");
    MAC2JBUSBFreeCapturedDescription(bytes);
    return result;
}

static MAC2JBUSBResult sole_to(CFDataRef input, const char *name,
                               int32_t configurationNumber, CFDictionaryRef *out) {
    uint8_t *bytes = NULL;
    size_t length = 0;
    MAC2JBUSBResult result = MAC2JBUSBSetSoleFunctionInDescriptionData(
        CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), name,
        configurationNumber, &bytes, &length);
    if (out) *out = NULL;
    if (result == MAC2JBUSBSuccess && out) *out = decode(bytes, length);
    if (result != MAC2JBUSBSuccess) check(bytes == NULL && length == 0,
                                         "rejected sole-set returned no buffer");
    MAC2JBUSBFreeCapturedDescription(bytes);
    return result;
}

static void expect_removal_rejected(CFDataRef input, const char *name,
                                    int32_t configurationNumber, const char *what) {
    CFDataRef out = NULL;
    check(remove_from(input, name, configurationNumber, &out) ==
          MAC2JBUSBFunctionRejected, what);
    check(out == NULL, what);
    if (out) CFRelease(out);
}

static CFArrayRef configurations_of(CFDictionaryRef info) {
    CFTypeRef value = CFDictionaryGetValue(info, CFSTR("ConfigurationDescriptors"));
    return value && CFGetTypeID(value) == CFArrayGetTypeID() ? (CFArrayRef)value : NULL;
}

static void expect_rejected(CFDataRef input, const char *name,
                            int32_t configurationNumber, const char *what) {
    CFDictionaryRef out = NULL;
    MAC2JBUSBResult result = append_to(input, name, configurationNumber, &out);
    check(result == MAC2JBUSBFunctionRejected, what);
    check(out == NULL, what);
    if (out) CFRelease(out);
}

int main(void) {
    CFDictionaryRef original = make_description();
    CFDataRef input = encode(original);
    if (!input) {
        fprintf(stderr, "FAIL could not encode the synthetic description\n");
        return 1;
    }

    CFDictionaryRef appended = NULL;
    check(append_to(input, "Mac2jbCanary", TARGET_CONFIGURATION, &appended) ==
          MAC2JBUSBSuccess, "append to the selected configuration succeeds");
    if (!appended) {
        fprintf(stderr, "FAIL no appended description was produced\n");
        CFRelease(input);
        CFRelease(original);
        return 1;
    }

    // Every device-level scalar and every other key is untouched: dropping the
    // configurations from both sides must leave two equal dictionaries.
    CFMutableDictionaryRef strippedOriginal = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, original);
    CFMutableDictionaryRef strippedAppended = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, appended);
    CFDictionaryRemoveValue(strippedOriginal, CFSTR("ConfigurationDescriptors"));
    CFDictionaryRemoveValue(strippedAppended, CFSTR("ConfigurationDescriptors"));
    check(CFEqual(strippedOriginal, strippedAppended),
          "device-level fields unchanged");
    check(CFDictionaryGetCount(original) == CFDictionaryGetCount(appended),
          "top-level field count unchanged");
    CFRelease(strippedOriginal);
    CFRelease(strippedAppended);

    CFArrayRef before = configurations_of(original);
    CFArrayRef after = configurations_of(appended);
    check(before && after, "both descriptions carry configurations");
    check(after && CFArrayGetCount(after) == CONFIGURATION_COUNT,
          "configuration count unchanged");
    for (CFIndex index = 0; before && after && index < CFArrayGetCount(after); index++) {
        CFDictionaryRef was = (CFDictionaryRef)CFArrayGetValueAtIndex(before, index);
        CFDictionaryRef is = (CFDictionaryRef)CFArrayGetValueAtIndex(after, index);
        if (index != TARGET_CONFIGURATION - 1) {
            check(CFEqual(was, is), "untargeted configuration unchanged");
            continue;
        }
        CFArrayRef wasNames = (CFArrayRef)CFDictionaryGetValue(was, CFSTR("Interfaces"));
        CFArrayRef isNames = (CFArrayRef)CFDictionaryGetValue(is, CFSTR("Interfaces"));
        CFIndex count = CFArrayGetCount(isNames);
        check(count == CFArrayGetCount(wasNames) + 1, "exactly one interface added");
        check(CFEqual(CFArrayGetValueAtIndex(isNames, count - 1), CFSTR("Mac2jbCanary")),
              "the new interface is last");
        // Existing interface numbers must not shift, so compare position by
        // position rather than as a set.
        for (CFIndex slot = 0; slot < count - 1; slot++) {
            check(CFEqual(CFArrayGetValueAtIndex(wasNames, slot),
                          CFArrayGetValueAtIndex(isNames, slot)),
                  "existing interface order unchanged");
        }
        CFMutableDictionaryRef trimmed = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, is);
        CFMutableArrayRef trimmedNames = CFArrayCreateMutableCopy(
            kCFAllocatorDefault, 0, isNames);
        CFArrayRemoveValueAtIndex(trimmedNames, count - 1);
        CFDictionarySetValue(trimmed, CFSTR("Interfaces"), trimmedNames);
        check(CFEqual(trimmed, was), "nothing else in the configuration changed");
        CFRelease(trimmedNames);
        CFRelease(trimmed);
    }
    CFRelease(appended);

    // A name already on the bus, in the target configuration or any other one.
    expect_rejected(input, "USBAudio2StreamOUT", TARGET_CONFIGURATION,
                    "duplicate in the target configuration refused");
    expect_rejected(input, "Valeria", TARGET_CONFIGURATION,
                    "duplicate in another configuration refused");
    expect_rejected(input, "Valeria", 1, "duplicate in configuration one refused");

    expect_rejected(input, "Mac2jbCanary", 0, "configuration zero refused");
    expect_rejected(input, "Mac2jbCanary", -1, "negative configuration refused");
    expect_rejected(input, "Mac2jbCanary", CONFIGURATION_COUNT + 1,
                    "configuration past the array refused");
    expect_rejected(input, "Mac2jbCanary", 256, "configuration above 255 refused");

    expect_rejected(input, "", TARGET_CONFIGURATION, "empty name refused");
    expect_rejected(input, "_leading", TARGET_CONFIGURATION,
                    "non-alphanumeric first character refused");
    expect_rejected(input, "has space", TARGET_CONFIGURATION, "space in name refused");
    expect_rejected(input, "has/slash", TARGET_CONFIGURATION, "slash in name refused");
    char tooLong[34];
    memset(tooLong, 'a', sizeof(tooLong) - 1);
    tooLong[sizeof(tooLong) - 1] = 0;
    expect_rejected(input, tooLong, TARGET_CONFIGURATION, "over-long name refused");

    // The accepted shape: trailing underscore, dot, dash and digits.
    CFDictionaryRef permitted = NULL;
    check(append_to(input, "0hid_canary.v1-a", TARGET_CONFIGURATION, &permitted) ==
          MAC2JBUSBSuccess, "permitted name characters accepted");
    if (permitted) CFRelease(permitted);

    uint8_t *bytes = NULL;
    size_t length = 0;
    check(MAC2JBUSBAppendFunctionToDescriptionData(NULL, 0, "Mac2jbCanary",
                                                   TARGET_CONFIGURATION, &bytes,
                                                   &length) == MAC2JBUSBInvalidInput,
          "missing plist refused as invalid input");

    // Whether every stock configuration carries an interface list is unknown.
    // An unrelated configuration without one must not sink the request, since
    // that would look like the device refusing the function; the configuration
    // actually being appended to must still carry one.
    for (int absent = 1; absent <= 2; absent++) {
        CFMutableDictionaryRef variant = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, original);
        CFMutableArrayRef list = CFArrayCreateMutableCopy(
            kCFAllocatorDefault, 0, configurations_of(original));
        int stripped = absent == 1 ? 1 : TARGET_CONFIGURATION;
        CFMutableDictionaryRef bare = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, CFArrayGetValueAtIndex(list, stripped - 1));
        CFDictionaryRemoveValue(bare, CFSTR("Interfaces"));
        CFArraySetValueAtIndex(list, stripped - 1, bare);
        CFDictionarySetValue(variant, CFSTR("ConfigurationDescriptors"), list);
        CFDataRef encoded = encode(variant);
        MAC2JBUSBResult result = append_to(encoded, "Mac2jbCanary",
                                           TARGET_CONFIGURATION, NULL);
        check(result == (absent == 1 ? MAC2JBUSBSuccess : MAC2JBUSBFunctionRejected),
              absent == 1 ? "another configuration without an interface list is skipped"
                          : "target configuration without an interface list refused");
        CFRelease(encoded);
        CFRelease(bare);
        CFRelease(list);
        CFRelease(variant);
    }

    // Undoing an append. The restore path has to take the appended function
    // back off a live description before it can prove it equal to the journaled
    // original, and this is the same helper that path runs, so it is proved
    // here on plist bytes with no controller.
    uint8_t *appendedBytes = NULL;
    size_t appendedLength = 0;
    check(MAC2JBUSBAppendFunctionToDescriptionData(
              CFDataGetBytePtr(input), (size_t)CFDataGetLength(input),
              "Mac2jbCanary", TARGET_CONFIGURATION,
              &appendedBytes, &appendedLength) == MAC2JBUSBSuccess,
          "append for the removal round trip succeeds");
    CFDataRef appendedData = appendedBytes
        ? CFDataCreate(kCFAllocatorDefault, appendedBytes, (CFIndex)appendedLength)
        : NULL;
    MAC2JBUSBFreeCapturedDescription(appendedBytes);
    if (!appendedData) {
        fprintf(stderr, "FAIL no appended bytes for the removal tests\n");
        CFRelease(input);
        CFRelease(original);
        return 1;
    }

    CFDataRef roundTrip = NULL;
    check(remove_from(appendedData, "Mac2jbCanary", TARGET_CONFIGURATION, &roundTrip) ==
          MAC2JBUSBSuccess, "removing the appended function succeeds");
    CFDictionaryRef restored = roundTrip
        ? decode(CFDataGetBytePtr(roundTrip), (size_t)CFDataGetLength(roundTrip))
        : NULL;
    check(restored && CFEqual(restored, original),
          "append then remove restores the original description");
    check(roundTrip && CFEqual(roundTrip, input),
          "append then remove restores the original bytes");
    if (restored) {
        CFMutableDictionaryRef wasScalars = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, original);
        CFMutableDictionaryRef isScalars = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, restored);
        CFDictionaryRemoveValue(wasScalars, CFSTR("ConfigurationDescriptors"));
        CFDictionaryRemoveValue(isScalars, CFSTR("ConfigurationDescriptors"));
        check(CFEqual(wasScalars, isScalars), "removal left device-level fields alone");
        check(CFDictionaryGetCount(original) == CFDictionaryGetCount(restored),
              "removal left the top-level field count alone");
        CFRelease(wasScalars);
        CFRelease(isScalars);
        CFArrayRef wasList = configurations_of(original);
        CFArrayRef isList = configurations_of(restored);
        check(isList && CFArrayGetCount(isList) == CONFIGURATION_COUNT,
              "removal left the configuration count alone");
        for (CFIndex index = 0; wasList && isList &&
             index < CFArrayGetCount(isList); index++) {
            // Position by position, so a shifted interface number would show.
            check(CFEqual(CFArrayGetValueAtIndex(wasList, index),
                          CFArrayGetValueAtIndex(isList, index)),
                  "removal left every configuration and interface order alone");
        }
        CFRelease(restored);
    }
    if (roundTrip) CFRelease(roundTrip);

    // Only the last interface of that configuration may go. Anything else
    // would let a restore drop an interface the stock device had.
    expect_removal_rejected(appendedData, "AppleUSBMux", TARGET_CONFIGURATION,
                            "a present but not last interface is refused");
    expect_removal_rejected(appendedData, "PTP", TARGET_CONFIGURATION,
                            "the first interface is refused");
    expect_removal_rejected(input, "Mac2jbCanary", TARGET_CONFIGURATION,
                            "an absent name is refused");
    expect_removal_rejected(appendedData, "Valeria", TARGET_CONFIGURATION,
                            "a name last in another configuration is refused");
    expect_removal_rejected(appendedData, "Mac2jbCanary", 1,
                            "removal from the wrong configuration is refused");
    expect_removal_rejected(appendedData, "Mac2jbCanary", 2,
                            "removal from an empty interface list is refused");

    expect_removal_rejected(appendedData, "Mac2jbCanary", 0,
                            "removal from configuration zero refused");
    expect_removal_rejected(appendedData, "Mac2jbCanary", -1,
                            "removal from a negative configuration refused");
    expect_removal_rejected(appendedData, "Mac2jbCanary", CONFIGURATION_COUNT + 1,
                            "removal past the configuration array refused");
    expect_removal_rejected(appendedData, "Mac2jbCanary", 256,
                            "removal above configuration 255 refused");

    expect_removal_rejected(appendedData, "", TARGET_CONFIGURATION,
                            "empty removal name refused");
    expect_removal_rejected(appendedData, "has space", TARGET_CONFIGURATION,
                            "space in the removal name refused");
    expect_removal_rejected(appendedData, tooLong, TARGET_CONFIGURATION,
                            "over-long removal name refused");

    bytes = NULL;
    length = 0;
    check(MAC2JBUSBRemoveFunctionFromDescriptionData(NULL, 0, "Mac2jbCanary",
                                                     TARGET_CONFIGURATION, &bytes,
                                                     &length) == MAC2JBUSBInvalidInput,
          "missing plist refused as invalid input on removal");

    // A configuration with no interface list at all cannot have a name removed.
    CFMutableDictionaryRef bareVariant = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, original);
    CFMutableArrayRef bareList = CFArrayCreateMutableCopy(
        kCFAllocatorDefault, 0, configurations_of(original));
    CFMutableDictionaryRef bareTarget = CFDictionaryCreateMutableCopy(
        kCFAllocatorDefault, 0, CFArrayGetValueAtIndex(bareList, TARGET_CONFIGURATION - 1));
    CFDictionaryRemoveValue(bareTarget, CFSTR("Interfaces"));
    CFArraySetValueAtIndex(bareList, TARGET_CONFIGURATION - 1, bareTarget);
    CFDictionarySetValue(bareVariant, CFSTR("ConfigurationDescriptors"), bareList);
    CFDataRef bareEncoded = encode(bareVariant);
    expect_removal_rejected(bareEncoded, "Mac2jbCanary", TARGET_CONFIGURATION,
                            "target configuration without an interface list refused");
    CFRelease(bareEncoded);
    CFRelease(bareTarget);
    CFRelease(bareList);
    CFRelease(bareVariant);
    CFRelease(appendedData);

    // Exclusive-HID shape: the selected configuration's interface list becomes
    // exactly the one function, every stock function in it removed, and
    // everything else left alone.
    CFDictionaryRef sole = NULL;
    check(sole_to(input, "Mac2jbCanary", TARGET_CONFIGURATION, &sole) ==
          MAC2JBUSBSuccess, "set sole function in the selected configuration succeeds");
    if (sole) {
        CFArrayRef soleConfigs = configurations_of(sole);
        check(soleConfigs && CFArrayGetCount(soleConfigs) == CONFIGURATION_COUNT,
              "sole-set keeps the configuration count");
        if (soleConfigs && CFArrayGetCount(soleConfigs) == CONFIGURATION_COUNT) {
            CFDictionaryRef target = (CFDictionaryRef)CFArrayGetValueAtIndex(
                soleConfigs, TARGET_CONFIGURATION - 1);
            CFArrayRef names = (CFArrayRef)CFDictionaryGetValue(target, CFSTR("Interfaces"));
            check(names && CFArrayGetCount(names) == 1,
                  "the selected configuration now carries exactly one interface");
            if (names && CFArrayGetCount(names) == 1) {
                check(CFEqual(CFArrayGetValueAtIndex(names, 0), CFSTR("Mac2jbCanary")),
                      "that one interface is the appended function");
            }
            // A different configuration (config 1) is untouched.
            CFDictionaryRef other = (CFDictionaryRef)CFArrayGetValueAtIndex(soleConfigs, 0);
            CFArrayRef otherNames = (CFArrayRef)CFDictionaryGetValue(other, CFSTR("Interfaces"));
            check(otherNames && CFArrayGetCount(otherNames) == 1 &&
                  CFEqual(CFArrayGetValueAtIndex(otherNames, 0), CFSTR("Valeria")),
                  "a non-target configuration is left exactly as it was");
        }
        // Device-level scalars are untouched: drop configurations and compare.
        CFMutableDictionaryRef wasScalars = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, original);
        CFMutableDictionaryRef isScalars = CFDictionaryCreateMutableCopy(
            kCFAllocatorDefault, 0, sole);
        CFDictionaryRemoveValue(wasScalars, CFSTR("ConfigurationDescriptors"));
        CFDictionaryRemoveValue(isScalars, CFSTR("ConfigurationDescriptors"));
        check(CFEqual(wasScalars, isScalars), "sole-set leaves every device scalar unchanged");
        CFRelease(wasScalars);
        CFRelease(isScalars);
        CFRelease(sole);
    }
    // A name already present in any configuration is refused, with no buffer.
    CFDictionaryRef collision = NULL;
    check(sole_to(input, "PTP", TARGET_CONFIGURATION, &collision) ==
          MAC2JBUSBFunctionRejected, "sole-set refuses a name already in the description");
    check(collision == NULL, "a refused sole-set yields no description");
    if (collision) CFRelease(collision);
    // A configuration out of range is refused.
    CFDictionaryRef outOfRange = NULL;
    check(sole_to(input, "Mac2jbCanary", CONFIGURATION_COUNT + 1, &outOfRange) ==
          MAC2JBUSBFunctionRejected, "sole-set refuses a configuration out of range");
    if (outOfRange) CFRelease(outOfRange);
    // A NULL input is refused and returns no buffer.
    uint8_t *nullOut = (uint8_t *)1;
    size_t nullLen = 1;
    check(MAC2JBUSBSetSoleFunctionInDescriptionData(NULL, 0, "Mac2jbCanary",
          TARGET_CONFIGURATION, &nullOut, &nullLen) == MAC2JBUSBInvalidInput,
          "sole-set refuses a NULL description");
    check(nullOut == NULL && nullLen == 0, "a refused sole-set clears the out buffer");

    // General list form: the usbmux-preserving shape keeps a stock subset and
    // adds the keyboard, as exactly the list given, in that order.
    {
        const char *const kept[] = {"PTP", "AppleUSBMux", "Mac2jbCanary"};
        uint8_t *bytes = NULL;
        size_t length = 0;
        check(MAC2JBUSBSetConfigurationInterfacesInDescriptionData(
                  CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), kept, 3,
                  TARGET_CONFIGURATION, &bytes, &length) == MAC2JBUSBSuccess,
              "set-interfaces to a stock subset plus the keyboard succeeds");
        CFDictionaryRef listed = (bytes ? decode(bytes, length) : NULL);
        if (listed) {
            CFArrayRef configs = configurations_of(listed);
            check(configs && CFArrayGetCount(configs) == CONFIGURATION_COUNT,
                  "set-interfaces keeps the configuration count");
            if (configs && CFArrayGetCount(configs) == CONFIGURATION_COUNT) {
                CFDictionaryRef target = (CFDictionaryRef)CFArrayGetValueAtIndex(
                    configs, TARGET_CONFIGURATION - 1);
                CFArrayRef names = (CFArrayRef)CFDictionaryGetValue(target, CFSTR("Interfaces"));
                check(names && CFArrayGetCount(names) == 3 &&
                      CFEqual(CFArrayGetValueAtIndex(names, 0), CFSTR("PTP")) &&
                      CFEqual(CFArrayGetValueAtIndex(names, 1), CFSTR("AppleUSBMux")) &&
                      CFEqual(CFArrayGetValueAtIndex(names, 2), CFSTR("Mac2jbCanary")),
                      "the selected configuration carries exactly the given list, in order");
            }
            CFRelease(listed);
        }
        MAC2JBUSBFreeCapturedDescription(bytes);
    }
    // Refusals: a duplicate in the list, an empty list, and a NULL list.
    {
        const char *const dup[] = {"PTP", "PTP"};
        uint8_t *bytes = (uint8_t *)1; size_t length = 1;
        check(MAC2JBUSBSetConfigurationInterfacesInDescriptionData(
                  CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), dup, 2,
                  TARGET_CONFIGURATION, &bytes, &length) == MAC2JBUSBFunctionRejected,
              "set-interfaces refuses a duplicate name");
        check(bytes == NULL && length == 0, "a refused set-interfaces clears the out buffer");
        const char *const one[] = {"Mac2jbCanary"};
        check(MAC2JBUSBSetConfigurationInterfacesInDescriptionData(
                  CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), one, 0,
                  TARGET_CONFIGURATION, &bytes, &length) == MAC2JBUSBInvalidInput,
              "set-interfaces refuses an empty list");
        check(MAC2JBUSBSetConfigurationInterfacesInDescriptionData(
                  CFDataGetBytePtr(input), (size_t)CFDataGetLength(input), NULL, 1,
                  TARGET_CONFIGURATION, &bytes, &length) == MAC2JBUSBInvalidInput,
              "set-interfaces refuses a NULL list");
    }

    CFRelease(input);
    CFRelease(original);
    if (failures) {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }
    printf("PASS USB description append and removal: appended last in the "
           "selected configuration, order and device fields unchanged, "
           "duplicate, configuration range and malformed names refused; "
           "append then remove restores the original bytes, and a name that "
           "is absent or not last is refused\n");
    return 0;
}
