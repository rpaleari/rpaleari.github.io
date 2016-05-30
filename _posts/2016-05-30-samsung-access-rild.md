---
layout: single
title: Interacting with Samsung radio layer (RILD)
excerpt: Samsung Android phones expose a local socket to communicate with RILD. Security checks protecting this socket can be circumvented, permitting any App to interact with the radio layer.
tags:
---

Last February I
[tweeted a video](https://twitter.com/rpaleari/status/701780929791008768){:target="_blank"}
showing how a local unprivileged applications can abuse an undisclosed
vulnerability affecting Samsung Android phones to perform "stealth calls"
(i.e., a voice call with no visible clue). This post discusses the technical
details behind that bug.

Several Samsung Android smartphones expose a UNIX socket, named "Multiclient",
that can be used by selected local applications to interact with RILD, the
Radio Interface Layer Daemon. Access to the "Multiclient" socket should be
limited to privileged applications only, as activities which can be performed
through this interface range from configuring low-level radio settings to
placing & receiving SMS messages and phone calls.

Unfortunately, restrictions imposed by Samsung to limit access to the
"Multiclient" socket can be bypassed, permitting _any_ local application to
interact with RILD, with no constraints.


## Accessing the Multiclient socket ##

Applications are supposed to interact with "Multiclient" socket (and thus with
RILD) by leveraging the APIs exposed by a user library, `libsecril-client.so`,
which abstracts away the details connected with managing the UNIX socket. On the
receiver-side, data sent through the socket is received by RILD using a second
library, `libsec-ril.so`, which unmarshals the request and eventually delivers
it to the underlying modem.

Library `libsecril-client.so` handles incoming socket connections through class
`OemClientReceiver`. Security checks that prevent unprivileged clients from
accessing the local socket are implemented right into
`OemClientReceiver::Accept()`. In a nutshell, the access control algorithm is
designed as follows:

1. `OemClientReceiver` calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` to retrieve
the PID and GID of the client.

2.  Using the client PID, `OemClientReceiver` reads `/proc/[pid]/cmdline` to
get the command-line associated to the client process. The string is tokenized
on white spaces to get the process name (i.e., the first token).

3. Finally, `OemClientReceiver` scans the `allowedProcess` global list,
containing tuples _(PID, GID, name)_ that identify authorized processed. If a
matching entry is found, then the client is allowed to connect.

{% include custom/image.html
  src="/images/posts/samsung-rild-allowed.png"
  caption="The global list of authorized processes (allowedProcess)"
%}

So, in order for an attacker app to impersonate an authorized process and
connect to the "Multiclient" process, it must be able to spoof the PID, GID,
and the name of a licit client.

The check on the PID/GID can be bypassed easily: a closer look at the
`allowedProcess` list reveals a single process, `com.expway.embmsserver`, with
both the PID _and_ GID set to `0xffffffff` (i.e., -1). As you probably imagine,
this special value instructs `OemClientReceiver` to accept any PID/GID for this
process.

However, the attacker still has to circumvent the last check, which involves
the process name. However, this is also quite a lax check, as processes are
free to alter the contents of `/proc/[pid]/cmdline` at their will. This is
demonstrated by the following C program (`cmdline.c`).

```c
#include <stdio.h>
#include <string.h>

static void get_cmdline(char *data, int size) {
  FILE *fp;
  fp = fopen("/proc/self/cmdline", "r");
  memset(data, 0, size);
  fread(data, size, 1, fp);
}

int main(int argc, char **argv) {
  if (argc == 1) {
	char* const args[] = {"/a/b/c/whatsoever", "x", NULL};
	execv(argv[0], args);
  } else {
	char cmdline[512];
	get_cmdline(cmdline, sizeof(cmdline));
	printf("Hi, my command line is: %s\n", cmdline);
  }
  return 0;
}
```

The `cmdline.c` program above rewrites its own command line to
`/a/b/c/whatsoever`, as demonstrated by the following execution:

```
$ ./cmdline
Hi, my command line is: /a/b/c/whatsoever
```

It should be clear that the contents of `argv[0]` cannot be trusted, and any
security check based on the contents of `/proc/[pid]/cmdline` can then be
bypassed. In our specific context, this approach can be abused by any local
application to access the "Multiclient" UNIX socket and interact with RILD.


## Level 1: Interacting with RILD ##

By leveraging the technique discussed in the previous section, we are now able
to connect to the "Multiclient" local socket. Library `libsecril-client.so`
provides some handy methods to establish the connection and perform some basic
actions, but most of the actions we can perform are undocumented. The only
notable exception of public documentation is the (unofficial)
[Samsung IPC library](https://github.com/ius/libsamsung-ipc){:target="_blank"}
and the
[Replicant project](https://git.replicant.us/replicant/hardware_samsung/){:target="_blank"}.

Practically speaking, the core function for interacting with RILD is
`InvokeOemRequestHookRaw`, which permits to invoke an _OEM method_ through an
RPC-like mechanism. The input structure to `InvokeOemRequestHookRaw` has the
following format:

```c
struct OEMRequestRawHeader {
   unsigned char main_cmd;
   unsigned char sub_cmd;
   unsigned short length;
};
```

The `OEMRequestRawHeader` header is then followed by zero or more bytes for
method-specific arguments. Fields `main_cmd` and `sub_cmd` determine the actual
RILD method being called; possible values are undocumented, and must be
inferred by analyzing library `libsec-ril.so`.

Overall, `InvokeOemRequestHookRaw` permits to invoke tens of _OEM
methods_. Possible actions range from sending raw APDUs to the UICC (SIM) card,
to start capturing network traffic into a local PCAP file.


## Level 2: Interacting with the modem ##

Under the hoods, each of the RPC-like methods exposed through the
`InvokeOemRequestHookRaw` interface is translated into an additional, internal
IPC call between RILD and the radio modem. One of the methods exposed,
`DoOemRawIpc`, provides direct access to this IPC channel, permitting
user-space clients to interact with the modem at a very low level.

Method `DoOemRawIpc` is basically another RPC layer. The input argument must
adhere the following format:

```c
struct OEMIPCHeader {
  uint16_t length;
  uint8_t msg_seq;
  uint8_t ack_seq;
  uint8_t main_cmd;
  uint8_t sub_cmd;
  uint8_t cmd_type;
  uint8_t data_len;
};
```

Here `main_cmd` and `sub_cmd` are completely different command IDs than those
for `OEMRequestRawHeader`, while `cmd_type` specifies which kind of operation
we're going to perform (e.g., get/set/execute). Similarly to
`OEMRequestRawHeader`, `OEMIPCHeader` can also be followed by zero or more data
bytes, encoding method-specific arguments.


## Profit! ##

To sum up, unprivileged local applications can interact with the radio modem by
leveraging the "Multiclient" socket. Existing mechanisms that protect this UNIX
socket from unauthorized access attempts can be circumvented.

As a very simple example, on our Samsung Galaxy S6 we invoked `DoOemRawIpc`
with `main_cmd=1` and `sub_cmd=2`. These parameters correspond to the
"_poweroff modem_" method that, as the name implies, suddenly shuts down the
radio modem (the modem is then restarted few seconds later). A proof-of-concept
is available
[here](https://github.com/ud2/advisories/blob/master/android/samsung/nocve-2016-0005/ril_poweroff.c).

For a more realistic example, we verified a local attacker can invoke
`DoOemRawIpc` with `main_cmd=2` and `sub_cmd=1` to issue a "silent call", i.e.,
a phone call to an attacker-chosen destination number, but with no visual
indication on the victim's phone. This is obviously a very dangerous behavior,
that could be easily exploited by a malicious application to perform really
"stealth" phone calls, without requiring any specific Android permission.

We notified Samsung about this vulnerability on February 22, 2016. Initially,
the deadline was set to May 22 (90 days), and then postponed to May 30. Samsung
finally addressed the vulnerability with
[this security update](http://security.samsungmobile.com/smrupdate.html){:target="_blank"}
(see SVE-2016-5733).


## Affected devices ##

We confirm the issues described in this advisory affect the following device
models. Other models and firmware versions are probably affected as well, but
they were not tested.

* SM-G920F, build G920FXXU2COH2 (Galaxy S6, patched with G920FXXU3DPDP)
* SM-N9005, build N9005XXUGBOK6 (Galaxy Note 3)
* GT-I9505, build I9505XXUHOJ2 (Galaxy S4)
