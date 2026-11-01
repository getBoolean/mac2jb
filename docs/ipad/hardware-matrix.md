# iPad hardware gate matrix

Redacted gate decisions for the iPad port's hardware plan (`docs/plans/ipad-port/01-hardware-feasibility.md`). Raw reports and captures stay in ignored `build/ipad-hardware/`; this file holds only decisions, limits and hashes. Reference device: M2 iPad Pro 12.9" (6th gen), `iPad14,5` / `J620AP` / `T8112`, iPadOS 17.0 `21A329`, Dopamine rootless, TrollStore. Dated checkpoint history was condensed on 2026-10-31 (see git history).

## Unit status

| Unit | Decision | Evidence boundary |
|---|---|---|
| U1 read-only target inventory | **Pass (2026-10-30)** | R1–R3 and U1-scoped R14, below. Read-only inventory, authorization and role/power only. |
| U2 restoration journal and watchdog | **Pass (2026-10-31)** | Automatic same-boot recovery: v11 5/5 and v12 2/2 hardware no-op trials. Semantic external equivalence; the `AllowMultipleCreates` flag is an accepted deviation. Below. |
| U3 additive HID canary | In progress; host side not yet observable | The device side works end to end: the appended function **registers with the controller**, materializes as an interface, its user client opens, and every configuration operation returns success. Whether a host can see it is **still unmeasured** - every attempt so far observed outside the window in which the function existed. All below. |
| U4 exclusive-HID fallback | Not tested | Conditional fallback only. |
| U5 network topology | Not tested | No paired 20-attempt exploit comparison. |
| U6 capability contract | Not tested | No signed final capability record. |

## U1 decision (2026-10-30): PASS for the read-only scope

The client, platform and ordinary baseline/set-description authorization profiles each have two validated reports on Mac A/B and on owner-reported direct Switch 2 A/B, with stable fingerprints. Six complete Mac USB lifecycle windows recorded zero target events and final presence. On Switch 2 the controller was configured, on bus and externally powered, without charging.

| Requirement | Evidence | Decision |
|---|---|---|
| R1 exact inventory | Target tuple, stock USB source (SHA-256 `a0f63c8c…1792c5fa`), one controller, 16 functions, twice-equal default/live descriptions matching one stock configuration list; `configuration-string` absent at the device-tree root. | Pass |
| R2 authorization boundaries | Ordinary in-process apps: controller opens unsupported (`-536870201`), function opens denied (`-536870174`); the set-description entitlement made no read-only difference. Publication needs `com.apple.private.usbdevice.setdescription` with `platform-application` in a root launchd job (plain apps are SIGKILLed before `main`). | Pass for classification |
| R3 direct role/power | Configured/on-bus with external power on both Switch 2 orientations; peer identity is owner-reported. | Pass (device side) |
| R14 evidence | Private reports, attestations, host-window bindings and stock-source snapshots retained in `build/ipad-hardware/`. | Pass |

## U3 operation matrix (2026-10-31): every configuration operation is authorized

Walked the configuration sequence one operation at a time, recording each raw
return and stopping at the first refusal. Nothing refused.

```
interface-open=0x00000000 set-class=0x00000000 set-subclass=0x00000000
set-protocol=0x00000000 append-standard=0x00000000 append-nonstandard=0x00000000
class-callbacks=0x00000000 create-pipe=0x00000000 commit=0x00000000
create-buffer=0x00000000 pipe-max-packet=0x00000000  aborted-by=255
```

Every selector number came from reading a macOS backend and was treated as a
hypothesis to test here, with neighbouring numbers to be probed if one reported
an unsupported selector. None did: **the reference numbering is correct on this
build**, including the user-client type. Device-side HID configuration works.

Two observations kept for the next gate: the pipe's current max packet size
reads 0 rather than 8 while no host has configured the interface, and this
heal needed one owner restart (`com.apple.audiomxd`) after two
re-publications, the first HID trial to need one.

## U3 host enumeration (2026-10-31): not yet measured, and why the rig could not measure it

**The host-side results so far are void, not negative.** An independent review
of the retained evidence established that no trial was positioned to see a
keyboard, and this section previously drew a conclusion the evidence does not
support.

The descriptor capture ran about ninety seconds after publication - past the
lease, and after the healer had re-published the stock description several
times. It measured a **stock** device and correctly reported that a stock
device has no keyboard interface:

```
outcome=interface-absent interfaces=8 reports=0
get-descriptor configuration=observed  set-configuration=observed
get-descriptor hid-report=not-observed
```

The device-side verdict was equally empty: the waiting process is bounded by
the lease, so every trial ended `lease-lost` rather than reaching an answer.

**The window was empty by construction.** This device takes 29-72 s to come
back on bus after a description change; the lease caps at 30 s; and the
mechanism that brings the bus back is the healer re-publishing the journaled
original, which deletes the appended function. So the function existed only
while the device was off bus, and the only thing that restored the bus also
removed the function.

What the device's own log does establish, decisively, is that the appended
function is accepted by the controller:

```
gated_registerFunction: register function Mac2jbCanary
```

It registers alongside the stock functions, and `remoted` reads the published
description with the appended name last in the host-selected configuration. The
two functions that failed to register in that trial were stock ones
(`Valeria`, `USBAudio2Control`), which is the ordinary registration race.

Issuing that cycle after the commit worked as an operation (`io=0x00000000`)
and made things worse overall. Replacing the description already races the
function re-registration; a second cycle while the appended interface was live
left **three** functions unregistered (`IapOverUsbHid`, `USBAudio2StreamOUT`,
`Valeria`) where every earlier trial lost one or two. Two are kernel-owned, so
the healer correctly declined owner restarts - it restarts owners only when
every missing function has one - fell back to re-publication, spent its bound
of five and gave up. Mac USB stayed down past the runner's 120 s wait.

Recovery followed the runbook and needed no reboot: pinned Wi-Fi SSH was
healthy throughout, one `restore-after-failure` healed with zero further
re-publications, the Mac saw the device again, and the journal was confirmed
only on the strict external check's own output. Interfaces, scalars, pairing
and packet flow all compared equal afterwards.

Publishing without the initial cycle and cycling once after the commit was
tried and is materially safer - USB returned unaided - but it did not make the
result observable, for the structural reason above.

### 2026-11-01: a fully configured interface, and the host still does not select it

With the broker surviving (jetsam limit raised) and the lease renewed across 12
quanta, the `configure-only` gate completed the whole sequence on device:

```
operations interface-open=0x00000000 set-class=0x00000000 set-subclass=0x00000000
  set-protocol=0x00000000 append-standard=0x00000000 append-nonstandard=0x00000000
  class-callbacks=0x00000000 create-pipe=0x00000000 commit=0x00000000
  create-buffer=0x00000000 pipe-max-packet=0x00000000/1 aborted-by=255
pipe max-packet=0 result=0 io=0x00000000 expected=8
enumeration host=never-enumerated polls=239 max-packet=0 io=0x00000000
```

Every operation returned success and nothing aborted: the class triple is set,
both descriptors are appended, the pipe exists, the buffer is mapped and
committed, and the class-command callbacks are registered. The bus was then
cycled (`bus-cycled io=0x00000000`). Across 120 s and 239 polls the pipe's
max packet size stayed **0** against an expected 8.

That size is the device's own answer to the question: it is non-zero only once a
host has selected a configuration containing the interface. Zero for two minutes
after a committed configuration and a bus cycle is strong device-side evidence
that **the host never selects the appended interface**, which is what the
reference model would predict if the controller fixes the host-visible
configuration descriptor when it builds the device object and a later commit
cannot reach the host.

It is not yet the host-side proof, and must not be written up as one. The
descriptor capture was still `void`: the bus cycle now takes the device off bus
for longer than the trial's 120 s reattach bound, so the capture ran after the
publication had gone. Closing that needs the reattach bound, the lease cap and
the canary's wait raised together past the observed outage - the same
"everything must move together" rule that the lease fix already taught.

**What remains genuinely unknown** is whether a configuration committed after
the kernel has built the device object can reach a host's configuration
descriptor on this controller. Nothing observed contradicts the reference's
model, and every device-side precondition is met; no trial has yet been
instrumented to ask the question. Answering it needs an observer that outlives
the device's own on-bus recovery and a heal path that re-publishes the intended
description rather than the bare original.

## U3 interface gate (2026-10-31): the appended function appears and opens

The plan's stop gate, and the largest unknown in the effort: whether this
controller materializes an **arbitrary** appended function name as an
`IOUSBDeviceInterface`, and whether userspace may open its user client. Both
answers are yes on this device.

The broker published the stock description plus one appended function; the
least-privileged process took the broker's lease, polled for the interface, and
made exactly one open attempt, configuring nothing.

```
lease=held function=Mac2jbCanary
open result=0 match=0x00000000 open=0x00000000 waits=6
open-gate outcome=opened exit=0
```

- The interface appeared after six polls, so it is created by the publication
  rather than pre-existing.
- The match and the open both returned success, with the open using only the
  interface user-client exception and `platform-application` - no
  set-description entitlement. That matches what the read-only survey measured
  for the stock interfaces and extends it to a name this port invented.
- Mac USB returned by itself after three bounded re-publications and no owner
  restarts; the strict external check passed and the journal was confirmed only
  on that check's own output.

A defect had to be fixed first, and it is worth recording because it presented
as a platform limit. The matcher reported a *successful* match that yielded
nothing as an unavailable controller rather than an absent service. The waiting
caller polls only on absent, so it gave up immediately (`waits=0`), released the
lease, and the publication was then refused for having no lease holder - three
steps downstream of the real cause. A review had already observed the same wrong
result from the Mac and it was mis-filed as weak test coverage; the assertion
that accepted either answer is what let it hide.

What this does not establish: which configuration operations the build
authorizes. Nothing was configured and nothing was typed.

## U3 open-only HID gate, first clean attempt (2026-11-01): a 17-function bus did not come up

The first gate attempt whose evidence is not spoiled by the runner killing the
lease holder (that bug is fixed). The broker published the stock description
plus one appended function (`Mac2jbCanary`).

- The kernel **accepted the appended name into the device description**
  (`createUSBDevice: interface: Mac2jbCanary`), so an arbitrary 17th function
  name is not rejected outright.
- The controller **did not come on bus** with the 17-function configuration:
  `goOnBus: not on bus`, no arrival across the whole window — not even the
  transient arrivals the earlier spoiled runs showed. So the earlier
  "transient then vanish" readings were, if anything, optimistic.
- The additive heal (which keeps the appended function under test) did 5
  republications, no owner restarts, and gave up with the audio functions and
  `Valeria` unregistered — the same race U2 characterized, here unrecovered
  within the republication bound.
- The canary never reached its single open attempt, because no
  `IOUSBDeviceInterface` service materialized while the controller was off bus.
  So this attempt does **not** answer R9's open/materialize question; it fails
  earlier, at bus liveness.
- USB recovered without a reboot: restoring the bare 16-function original came
  on bus in 2 republications, the strict check passed, and the journal cleared.

Not yet recorded as a gate decision. One lead is open: the additive heal did no
owner restarts despite a user-space-owned function (`Valeria`/`audiomxd`) being
among the missing, which is being investigated in code before any further trial.

## U3 first device trial (2026-10-31): a changed description recovers

The first publication on this device that was **not** a no-op. The broker
published the stock description plus one appended function and nothing
configured that function, which separates "does a changed description still
recover" from HID itself: a difference here cannot be blamed on HID.

- Mac USB dropped on publication and returned **with no owner action in 51 s**,
  after three bounded re-publications and no owner restarts.
- The strict external check passed afterwards, and the journal was confirmed
  only with that check's own output as proof, then re-checked absent.
- The restored description carries **no** appended function: the live function
  census has no occurrence of the published name, and the learned profile is
  unchanged at 16 functions.

Against the no-op baseline the extra function did not measurably worsen the
function-registration race: the earlier trials recovered in 29-72 s, and one of
them used all five permitted re-publications where this used three. Owner
restarts were needed in some earlier trials and in none here.

What this does not establish: whether the kernel materializes the appended name
as a gadget interface at all, which is the next gate and the plan's stop
condition if it fails. Nothing was configured, opened or typed.

## U2 decision (2026-10-31): PASS, automatic recovery

The broker journals the live description, publishes through the controller clone and heals automatically. After a description swap the controller waits for every USB function to re-register. The broker re-publishes a bounded number of times and restarts the user-space owner of a function that failed to register (see `usb-auto-recovery.md`). The healing covers a failed first enumeration, worker death, watchdog restart and lease expiry.

| Broker | Trials | Result |
|---|---|---|
| v11 `8fdb044f…` | normal ×3, worker-kill, watchdog-kill | 5/5 recovered without owner action in 46–61 s (1–3 re-publications, two with an `audiomxd` restart) |
| v12 `96296113…` (learned device profile) | normal, watchdog-kill | 2/2 recovered in 72 s (5 re-publications plus `audiomxd`) and 29 s (1 re-publication) |

Every trial then passed the strict external check against a twice-stable current-boot baseline (`u2-v9-trial-baseline`, manifest `30693c83…18de`):
- five raw configurations with all 23 resolved strings equal;
- equal host interfaces and device scalars;
- NCM driver binding and a packet reply;
- one USBMux device, valid pairing, and power.

Each journal was confirmed only with the SHA-256 of that check's output and re-checked with no journal.

**Accepted deviation:** the live registry description keeps `AllowMultipleCreates=true` as an extra field. The publication path requires it; the other fields equal the stock original. String-descriptor indexes may be renumbered while every resolved string stays equal.

**Limits:** these are seven hardware trials, not the release plan's 30-cycle qualification, and one trial used the full re-publication bound. Fixture coverage is in `docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-*.py`.
