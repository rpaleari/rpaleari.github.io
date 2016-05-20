---
layout: single
title: 'Time to fill OS X (Blue)tooth: Local privilege escalation vulnerabilities in Yosemite'
date: '2015-01-12T15:59:00.001+01:00'
modified: '2015-02-08T18:28:47.108+01:00'
excerpt: A post about multiple security issues affecting the IOBluetoothHCIController OS X kernel extension (Yosemite).
tags:
---

{% include custom/joint.html nick="@joystick" id="joystick" %}

Motivated by our
[previous findings](http://randomthoughts.greyhats.it/2014/10/osx-local-privilege-escalation.html),
we performed some more tests on service `IOBluetoothHCIController` of the latest
version of Mac OS X (Yosemite 10.10.1), and we found five additional security
issues. The issues have been reported to Apple Security and, since the deadline
we agreed upon with them expired, we now disclose details & PoCs for four of
them (the last one was notified few days later and is still under investigation
by Apple). All the issues are in class `IOBluetoothHCIController`, implemented in
the `IOBluetoothFamily` kext (md5 `e4123caff1b90b81d52d43f9c47fec8f`).


## Issue 1 ([crash-issue1.c](http://goo.gl/8i2y5k)) ##

Many callback routines handled by `IOBluetoothHCIController` blindly dereference
pointer arguments without checking them. The caller of these callbacks,
`IOBluetoothHCIUserClient::SimpleDispatchWL()`, may actually pass NULL pointers,
that are eventually dereferenced.

More precisely, every user-space argument handled by `SimpleDispatchWL()`
consists of a value and a size field (see
[crash-issue1.c](http://goo.gl/8i2y5k) for details). When a user-space client
provides an argument with a NULL value but a large size, a subsequent call to
`IOMalloc(size)` fails, returning a NULL pointer that is eventually passed to
callees, causing the NULL pointer dereference.

The PoC we provide targets method `DispatchHCICreateConnection()`, but the very
same approach can be used to cause a kernel crash using other callback routines
(basically any other callback that receives one or more pointer arguments). At
first, we ruled out this issue as a mere local DoS. However, as discussed here,
Yosemite only partially prevents mapping the NULL page from user-space, so it
is still possible to exploit NULL pointer dereferences to mount LPE
attacks. For instance, the following code can be used to map page zero:

```c
Mac:tmp $ cat zeropage.c

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  mach_vm_address_t addr = 0;
  vm_deallocate(mach_task_self(), 0x0, 0x1000);
  int r = mach_vm_allocate(mach_task_self(), &addr, 0x1000, 0);
  printf("%08llx %d\n", addr, r);
  *((uint32_t *)addr) = 0x41414141;
  printf("%08x\n", *((uint32_t *)addr));
  }

Mac:tmp $ llvm-gcc -Wall -o zeropage{,.c} -Wl,-pagezero_size,0 -m32
Mac:tmp $ ./zeropage
00000000 0
41414141
Mac:tmp $
```

Trying the same without the `-m32` flag results in the 64-bit Mach-O being
blocked at load time by the OS with message "_Cannot enforce a hard page-zero
for ./zeropage_" (unless you do it as "`root`", but then what’s the point?).


## Issue 2 ([crash-issue2.c](http://goo.gl/teK3lo)) ##

As shown in the screenshot below,
`IOBluetoothHCIController::BluetoothHCIChangeLocalName()` is affected by an
"old-school" stack-based buffer overflow, due to a `bcopy(src, dest,
strlen(src))` call where src is fully controlled by the attacker. To the best
of our knowledge, this bug cannot be directly exploited due to the existing
stack canary protection. However, it may still be useful to mount a LPE attack
if used in conjunction with a memory leak vulnerability, leveraged to disclose
the canary value.

{% include custom/image.html
  src="/images/posts/osx-IOBluetoothFamily-bcopy.png" width="682"
  caption="Issue 2, a plain stack-based buffer overflow"
%}


## Issue 3 ([crash-issue3.c](http://goo.gl/q0fRLo)) ##

`IOBluetoothHCIController::TransferACLPacketToHW()` receives as an input
parameter a pointer to an `IOMemoryDescriptor` object. The function carefully
checks that the supplied pointer is non-NULL; however, regardless of the
outcome of this test, it then dereferences the pointer (see the figure below,
the attacker-controlled input parameter is stored in register `r15`). The
`IOMemoryDescriptor` object is created by the caller
(`DispatchHCISendRawACLData()`) using the `IOMemoryDescriptor::withAddress()`
constructor. As this constructor is provided with a user-controlled value, it
may fail and return a NULL pointer. See Issue 1 discussion regarding the
exploitability of NULL pointer dereferences on Yosemite.

{% include custom/image.html
  src="/images/posts/osx-IOBluetoothFamily-null.png" width="459"
  caption="Issue 3, the module checks if r15 is NULL, but dereferences it anyway"
%}


## Issue 4 ([lpe-issue1.c](http://goo.gl/EVTTND)) ##

In this case, the problem is due to a missing sanity check on the arguments of
the following function:

```c
IOReturn BluetoothHCIWriteStoredLinkKey(
  uint32_t req_index,
  uint32_t num_of_keys,
  BluetoothDeviceAddress *p_device_addresses,
  BluetoothKey *p_bluetooth_keys,
  BluetoothHCINumLinkKeysToWrite *outNumKeysWritten
);
```

The first parameter, `req_index`, is used to find an HCI Request in the queue
of allocated HCI Requests (thus this exploit requires first to fill this queue
with possibly fake requests). The second integer parameter (`num_of_keys`) is
used to calculate the total size of the other inputs, respectively pointed by
`p_device_addresses` and `p_bluetooth_keys`. As shown in the screenshot below,
these values are not checked before being passed to function
`IOBluetoothHCIController::SendHCIRequestFormatted()`, which has the following
prototype:

```c
IOReturn SendHCIRequestFormatted(
  uint32_t req_index, uint16_t inOpCode,
  uint64_t outResultsSize,
  void *outResultBuf,
  const char *inFormat, ...
);
```

{% include custom/image.html
  src="/images/posts/osx-IOBluetoothFamily-writestoredlinkkey.png" width="650"
  caption="Issue 4, an exploitable buffer overflow (click to enlarge)"
%}

The passed format string "`HbbNN`" will eventually cause `size_of_addresses`
bytes to be copied from `p_device_addresses` to the HCI request object
identified by `req_index` in reverse order (the '`N`' format consumes two
arguments, the first is a size, the second a pointer to read from). If the
calculated `size_of_addresses` is big enough (i.e., if we provide a big enough
`num_of_keys` parameter), the copy overflows the buffer of the request,
thrashing everything above it, including a number of function pointers in the
vtable of the request object. These pointers are overwritten with
attacker-controlled data (i.e., those pointed by `p_bluetooth_keys`) and called
before returning to userspace, thus we can divert the execution wherever we
want.

As a PoC, [lpe-issue1.c](http://goo.gl/EVTTND) exploits this bug and attempts
to call a function located at the attacker-controller address
`0x4141414142424242`. Please note that the attached PoC requires some more
tuning before it can cleanly return to user-space, since more than one vtable
pointer is corrupted during the overflow and needs to be fixed with valid
pointers.


## Notes ##

All the PoCs we provide in this post are not "weaponized", i.e., they do not
contain a real payload, nor they attempt to bypass existing security features
of Yosemite (e.g., kASLR and SMEP). If you’re interested in bypass techniques
(as you probably are, if you made it here), Ian Beer of Google Project Zero
covered pretty much all of it in a very thorough
[blog post](http://googleprojectzero.blogspot.it/2014/11/pwn4fun-spring-2014-safari-part-ii.html). In
this case, he used a leak in the IOKit registry to calculate `kslide` and defeat
kASLR, while he used an in-kernel ROP-chain to bypass SMEP. More recently,
[@i0n1c](https://twitter.com/i0n1c) posted
[here](https://www.sektioneins.de/en/blog/14-12-23-mach_port_kobject.html)
about how kASLR is fundamentally broken on Mac OS X at the moment.


## Conclusions ##

Along the last issue identified, we shared with Apple our conclusions on this
kext: according to the issues we identified, we speculate there are many other
crashes and LPE vulnerabilities in it. Ours, however, is just a best-effort
analysis done in our spare time, and given the very small effort that took us
to identify the vulnerabilities, we would suggest a serious security evaluation
of the whole kext code.


## Disclosure timeline ##

* **02/11**: Notification of issues 1, 2 and 3.
* **23/11**: No answer received from Apple, notification of issue 4. As no answer was received since the first contact, propose December 2 as possible disclosure date.
* **25/11**: Apple answers requesting more time. We propose to move the disclosure date to January 12.
* **27/11**: Apple accepts the new deadline.
* **05/12**: Contact Apple asking for the status of the vulnerabilities.
* **06/12**: Apple says they're still "investigating the issue".
* **23/12**: Notification of a new issue (#5), proposing January 23 as a tentative disclosure date.
* **06/01**: Apple asks for more time for issue #5. We propose to move the disclosure date to February 23. We remind our intention to disclose the 4 previous issues on January 12.
* **12/01**: No answer from Apple, disclosing first 4 issues.
* **27/01**: Apple assigned our issues CVE-2014-8837 and patched all of them in Mac OS X 10.10.2.
