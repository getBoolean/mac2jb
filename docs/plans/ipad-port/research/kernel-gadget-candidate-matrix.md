# Kernel gadget source-only candidate matrix

This is the source-only gate for a kernel-matched USB function on the reference
M2 iPad. It does not report a device experiment and does not claim that such a
driver is impossible. It asks a narrower question: does published source and
retained repository evidence presently identify a candidate that is volatile,
removable in the same boot by an independent owner, capable of binding a USB
function nub, and capable of later carrying HID reports?

**Verdict: source-only stop.** No candidate satisfies all of those conditions.
The next read-only device-profile gate therefore has no eligible input and must
not run. A later source discovery can reopen this gate by changing a candidate's
classification and passing the validator.

## Evidence boundary

- [KTRW](https://github.com/googleprojectzero/ktrw) is real third-party iOS
  kernel-code prior art, but its published paths depend on an A11-only KTRR
  bypass or checkra1n/pongoOS preboot insertion. Its example kext has no IOKit
  personalities and its USB debugger directly takes over the Synopsys USB2
  controller; it is not a removable gadget-function driver.
- [KCMod](https://github.com/skr0x1c0/kcmod) and
  [insert_kext](https://github.com/mowisec/insert_kext) modify a research
  kernelcache/fileset. `insert_kext` demonstrates code execution and creation
  of a stock `IOService`, while documenting the unresolved PAC-signed-vtable
  boundary for a new arm64e class. Those mechanisms are boot-image replacement,
  not volatile same-boot candidates.
- [Synacktiv's iOS USB analysis](https://www.synacktiv.com/publications/ios-a-journey-in-the-usb-networking-stack)
  shows that `createUSBDevice` matches each described function to an in-kernel
  driver. A match-path bypass alone therefore does not implement the function's
  endpoint or report behavior.
- The retained matching investigation in
  [`usb-auto-recovery.md`](../../../ipad/usb-auto-recovery.md) identifies
  `IOCatalogue::addDrivers` as the generic rematch boundary, but also records
  that the available userspace path is gated and that a modified personality
  may remain until reboot. It supplies neither source-supported same-boot
  removal nor an independent rollback owner.
- The retained census identifies `IapOverUsbHid` bound by
  `IOAccessoryPortUSB` as the strongest concrete stock-class candidate. The
  userspace trials in
  [`target-device-findings.md`](../../../ipad/target-device-findings.md) prove
  that stock functions have working kernel matches, but neither the census nor
  the trials identify a descriptor API or caller-owned keyboard-report path on
  `IOAccessoryPortUSB` (or on another stock class).

## Human-readable comparison

| Candidate | What the sources establish | Decisive source-only blocker |
|---|---|---|
| Reuse a stock class and its existing personality | `IapOverUsbHid` binds to `IOAccessoryPortUSB`; other stock USB functions also bind and enumerate. | No retained source identifies a caller-owned keyboard descriptor/report path on that class or another stock class. |
| Add a personality targeting an existing stock class | Catalogue addition is the generic rematch mechanism in IOKit. | No suitable class is identified, and same-boot personality removal is not source-supported. |
| Load new code that calls existing classes | KTRW and research-kernelcache projects prove narrower code-execution precedents. | The published mechanisms are target-specific or persistent and provide no same-boot removal owner on this target. |
| Define a new arm64e class and personality | `insert_kext` can instantiate stock `IOService`. | A PAC-valid custom vtable remains unresolved, and the available injection path replaces the boot image. |
| Patch only the match/entitlement path | A narrow patch could change admission or matching behavior in principle. | Admission is not a function implementation; it provides neither binding behavior nor a HID report transport. |

The `highest_public_evidence` field deliberately records the strongest relevant
public or retained evidence, not a claim about the reference device. States
below `function-bound` cannot advance even when code execution itself is real.

<!-- candidate-matrix:start -->
```json
{
  "schema_version": 1,
  "verdict": "source-only-stop",
  "candidates": [
    {
      "id": "existing-class-reuse",
      "mechanism": "Reuse a stock USB function class and its existing personality without new kernel code; the strongest retained example is IapOverUsbHid bound by IOAccessoryPortUSB.",
      "executable_code": "not-required",
      "pac_vtable": "not-required",
      "catalogue_mutation": "not-required-if-existing-personality-matches",
      "persistence": "volatile",
      "same_boot_removal": "source-supported",
      "rollback_owner": "surviving-independent-owner",
      "build_dependence": "class-and-personality-specific",
      "hid_report_path": "not-identified",
      "highest_public_evidence": "function-bound",
      "source_disposition": "stop",
      "blockers": [
        "IOAccessoryPortUSB is evidenced as the kernel client for IapOverUsbHid, but no retained source shows that it accepts caller-defined keyboard descriptors or reports.",
        "No other identified stock class matches a caller-defined HID function and exposes a caller-owned HID report transport."
      ]
    },
    {
      "id": "catalogue-existing-class",
      "mechanism": "Add an IOCatalogue personality that targets an existing Apple class.",
      "executable_code": "not-required",
      "pac_vtable": "not-required",
      "catalogue_mutation": "required",
      "persistence": "volatile",
      "same_boot_removal": "not-source-supported",
      "rollback_owner": "not-demonstrated",
      "build_dependence": "exact-class-and-match-keys",
      "hid_report_path": "not-identified",
      "highest_public_evidence": "personality-installed",
      "source_disposition": "stop",
      "blockers": [
        "No suitable existing gadget-function class is identified.",
        "Modified catalogue entries may survive until reboot; bounded same-boot removal is not established.",
        "No independent rollback owner is demonstrated."
      ]
    },
    {
      "id": "volatile-code-existing-classes",
      "mechanism": "Place new executable code that composes or calls existing IOKit classes.",
      "executable_code": "required",
      "pac_vtable": "depends-on-design",
      "catalogue_mutation": "likely-required",
      "persistence": "boot-image-replacement",
      "same_boot_removal": "reboot-only",
      "rollback_owner": "none",
      "build_dependence": "target-and-build-specific",
      "hid_report_path": "design-only",
      "highest_public_evidence": "code-executed",
      "source_disposition": "stop",
      "blockers": [
        "Published iOS loaders are exceptional target-specific or preboot/kernelcache mechanisms.",
        "No volatile executable placement and same-boot cleanup path is identified for the reference target.",
        "Code execution alone does not prove a USB function binding."
      ]
    },
    {
      "id": "new-arm64e-class",
      "mechanism": "Inject a new arm64e IOKit class plus a matching USB function personality.",
      "executable_code": "required",
      "pac_vtable": "required-and-unresolved",
      "catalogue_mutation": "required",
      "persistence": "boot-image-replacement",
      "same_boot_removal": "reboot-only",
      "rollback_owner": "none",
      "build_dependence": "target-and-build-specific",
      "hid_report_path": "design-only",
      "highest_public_evidence": "service-registered",
      "source_disposition": "stop",
      "blockers": [
        "The public arm64e injection example stops at a stock IOService because a PAC-valid custom vtable is unresolved.",
        "The demonstrated mechanism replaces a research kernelcache rather than loading and unloading volatile code.",
        "A registered service is not a bound USB function driver."
      ]
    },
    {
      "id": "match-path-patch",
      "mechanism": "Patch only a narrow createUSBDevice admission, entitlement, or matching decision.",
      "executable_code": "not-required-if-data-patch",
      "pac_vtable": "not-required",
      "catalogue_mutation": "not-required",
      "persistence": "volatile",
      "same_boot_removal": "designable-but-not-demonstrated",
      "rollback_owner": "not-demonstrated",
      "build_dependence": "exact-build-patch-site",
      "hid_report_path": "none",
      "highest_public_evidence": "entry-called",
      "source_disposition": "stop",
      "blockers": [
        "Bypassing admission or a match decision does not implement a USB function driver.",
        "No endpoint or HID report behavior is supplied.",
        "No surviving same-boot rollback owner is demonstrated."
      ]
    }
  ]
}
```
<!-- candidate-matrix:end -->

## Reopening condition

Reopen the gate only with source evidence for at least one candidate that is
volatile, has source-supported same-boot removal through an independent owner,
reaches actual USB function binding rather than an intermediate evidence state,
and exposes a credible HID report path. Until then, target reads cannot answer
the missing design questions and would not change this verdict.
