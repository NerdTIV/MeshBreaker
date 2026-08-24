# Getting a BLE target to practise on

Most of MeshBreaker needs something to point at, and the usual advice — buy a
dev board — is a poor first step. You already own a device that can act as a
BLE peripheral: your phone. It takes about a minute to set up, costs nothing,
and it is yours, which is the part that matters.

**Only ever point this tool at hardware you own or have written permission to
test.** Everything else in range belongs to a neighbour, a colleague or a
passer-by. A BLE scan is passive and harmless; connecting and writing is not.

## Android — nRF Connect

Nordic's nRF Connect can act as both an advertiser and a GATT server.

1. `⋮` → **Configure GATT server** → **Add service**. Add at least one
   characteristic with **WRITE** and **READ**. Without this you advertise
   nothing worth looking at.
2. **ADVERTISER** tab → **+**. Tick **Connectable**, add *Complete Local
   Name*, save.
3. Flip the switch on the configuration to **ON**.

Configure the GATT server *before* starting the advertiser.

## iOS — LightBlue

nRF Connect for iOS has neither an advertiser nor a GATT server; those are
Android-only. Use **LightBlue** (Punch Through) instead.

1. **Virtual Devices** tab.
2. **Heart Rate Monitor** gives you a working peripheral immediately, with a
   standard Heart Rate Control Point that accepts writes. **Blank** lets you
   define your own characteristics but needs more setting up.
3. Start advertising.

## What will bite you

**iOS rotates its address.** Roughly every fifteen minutes the peripheral
comes back on a new random address, and a MAC you noted earlier is stale. If
a probe says *"Device with address ... was not found"*, rescan and pick the
address up again by name.

**The app has to stay in the foreground.** Both platforms stop advertising
when the app is backgrounded or the screen locks.

**The name you ask for is not always the name you get.** Android often
advertises the system Bluetooth name instead. Search by the name you actually
see in a scan, not the one you typed.

**Phones answer slowly and drop links.** A phone is a fine target for
learning the workflow, and a poor one for judging a stack's robustness — it
will tear a connection down where an embedded device would answer with an
error code.

## Using it

Find it, then ask what it exposes:

```bash
meshbreaker recon -t 15
meshbreaker recon --fuzzable AA:BB:CC:DD:EE:FF
```

`--fuzzable` connects and counts the characteristics a fuzzer could write to.
A scan cannot tell you this: nothing in an advertisement says whether a
device accepts connections, and characteristics only exist once service
discovery has run. It never chooses targets by itself — you name them, or you
pass `scanned` to sweep everything the scan found, which is only reasonable
in a lab where you own every radio.

Then the rest of the chain:

```bash
meshbreaker set-target AA:BB:CC:DD:EE:FF
meshbreaker enumerate --no-sdp
meshbreaker fuzz -m gatt
```

## Reading the result

A phone will usually terminate the connection rather than accept a malformed
write. MeshBreaker reports that as a link loss and stops, telling you how
many payloads went unsent — a target that hangs up is a finding, but it is
not a crash, and the run that follows it is worthless if the tool keeps
writing into a dead connection.
