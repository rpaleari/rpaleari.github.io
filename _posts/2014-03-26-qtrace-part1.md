---
layout: single
title: Introducing QTrace, a "zero knowledge" system call tracer
date: '2014-03-26T16:28:00.000+01:00'
modified_time: '2015-01-10T19:34:29.586+01:00'
excerpt: "QTrace is a syscall tracer that requires no information about the structure of arguments, as it infers their format by observing kernel memory access patterns."
tags:
---

It has been a while since my last post on this blog (one year!), but I have
been quite busy both with my work and personal matters, including my wedding
:-). Today, I would like to break the silence to introduce **QTrace**, a "_zero
knowledge_" system call tracer I have just released open source.

**TL;DR**: _QTrace is yet-another (Windows) system call tracer. Its peculiarity
is that it requires **no information** about the structure of system call
arguments: the tracer can infer their format automagically, by observing kernel
memory access patterns. QTrace also includes a taint-tracking module to
identify data dependencies between system calls_.


## Please, not another syscall tracer! ##

![image-right]({{ site.url }}{{ site.baseurl }}/images/posts/qtrace-syscall.png){: .align-right}

Some time ago I was writing an IOCTL fuzzer to test a Windows device
driver. The fuzzer itself was pretty standard stuff: intercept the IOCTLs
issued by the driver, fuzz the input buffer and monitor what
happens. Unfortunately, blindly fuzzing IOCTL input buffers, without any idea
of their format is usually ineffective, especially when facing structured
arguments, and can reveal only shallow bugs. The typical solution is to
undertake a boring reverse engineering session to determine the structure of
the input data the kernel driver is expecting, and adapt the fuzzer
accordingly. A somehow similar problem arose when I was developing
[WUSSTrace](https://code.google.com/p/wusstrace/), a user-space syscall tracer
for Windows. That time we relied on some
[preprocessor macros](https://code.google.com/p/wusstrace/source/browse/trunk/libwst/serialize.hh)
to recursively serialize system call arguments with as little code as
possible. This approach was great to save some coding, but we still had to
provide the tracer with the prototypes for all Windows system calls, together
with the definitions for all the data types used by their arguments. Even if
some of them are well-documented, others aren't, especially when moving to GUI
(i.e., `win32k.sys`) syscalls.

But wouldn't it be nice if it was possible to automatically infer the format of
system calls input arguments, in a (almost) OS-independent manner? This is
exactly what QTrace tries to do!


## QTrace in a nutshell ##

QTrace is a "_zero knowledge_" system call tracer. Its main characteristic is
that system call arguments are dumped without the need to instruct the tracer
about their structure. The only information explicitly provided to QTrace are
the names of the system calls, but this is required just for "pretty printing"
purposes (saying "`NtOpenFile`" is way better than just "`0xb3`"). This also makes
QTrace almost OS-independent, at least when moving to different Windows
versions.

The basic idea behind QTrace is that arguments structures can be determined by
**observing kernel memory access patterns**: during the execution of a system
call, if the kernel accesses a user-space memory address, then this location
must belong to a system call argument, with only few exceptions (credits for
this nice idea go to [Lorenzo](http://martignlo.greyhats.it/)). Similarly,
user-space data pointers can be recognized by observing the kernel accessing a
location whose address has also been previously read from user-space.

Practically speaking, QTrace is implemented on top of
[QEMU](http://wiki.qemu.org/Main_Page) and includes two main modules: the
system call tracer itself and a dynamic taint-tracking engine. The former
implements the "_zero knowledge_" syscall tracing technique just described,
while the latter is used to track data dependencies (use/def) between system
call arguments (more about this later). Traced system calls, together with
taint information, are serialized to a protobuf stream and can be parsed
off-line. QTrace also includes some basic Python post-processing tools to parse
and display syscall traces in a human-readable form; recorded system calls can
be even re-executed.

For the rest of this post we are assuming we are dealing with a 32-bit Windows
system, but the same approach can be adapted to 64-bit environments as well.


## Example: Syscall tracing ##

Imagine the Windows kernel is reading a `UNICODE_STRING` syscall argument located
at address `0x0205e2ac`. The definition for this structure is provided below;
inline comments specify field offsets and sample values.

```c
typedef struct _UNICODE_STRING {
  USHORT Length;          // Offset 0, value: 0x0042
  USHORT MaximumLength;   // Offset 2, value: 0x021a
  PWSTR  Buffer;          // Offset 4, value: 0x02bd11a0
} UNICODE_STRING, *PUNICODE_STRING;
```

To access the Unicode data buffer (field "`Buffer`") the kernel will first
access user-space address `0x0205e2b0` (corresponding to `0x0205e2ac+4`) and
read a pointer from there (value `0x02bd11a0`). Then, kernel will start
accessing 0x42 bytes starting at address `0x02bd11a0`. By observing this memory
access pattern, we can reconstruct the overall layout of the `UNICODE_STRING`
parameter.

To give an idea about the information that can be inferred through this
approach, figure below shows an excerpt of a sample QTrace trace file from a
Windows 7 system. In this case, process `explorer.exe` executed a
`NtOpenFile()` system call, passing six arguments. As an example, the third
argument (at `0x0205e258`) is a pointer to a structure located at address
`0x0205e274`; this structure includes a data pointer (at offset 8) to
`0x0205e2ac`, which in turn has a data pointer (at offset 4) pointing to the
Unicode string "`\??\C:\Windows\System32\pnpui.dll`".

{% include custom/image.html
  src="/images/posts/qtrace-log.png" width="753"
  caption="Sample QTrace log file for a NtOpenFile system call (Windows 7)"
%}

We can assess the correctness of this information by checking
[Microsoft documentation](http://msdn.microsoft.com/en-us/library/windows/hardware/ff567011%28v=vs.85%29.aspx)
for the prototype of this system call:

```c
NTSTATUS ZwOpenFile(
  _Out_  PHANDLE FileHandle,
  _In_   ACCESS_MASK DesiredAccess,
  _In_   POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_  PIO_STATUS_BLOCK IoStatusBlock,
  _In_   ULONG ShareAccess,
  _In_   ULONG OpenOptions
);
```

Third parameter of `NtOpenFile()` is actually a pointer to a
`OBJECT_ATTRIBUTES` structure, which contains a `UNICODE_STRING` (at offset 8),
that in turn contains a wide-character buffer (at offset 4) that provides the
name of the file to be opened. Except for parameter names (which of course
cannot be guessed), inferred arguments structure matches the official
documentation. Obviously things are slightly more complicated than this, as
there are some corner-cases that must be considered, but this should give a
rough idea of the approach.


## Example: Taint-tracking ##

Briefly, in our context system call B depends on system call A if one of the
output arguments of A is eventually used as an input argument for B. The reason
why we could be interested in recording this kind of information is that
syscall B cannot be re-executed alone, as it probably leverages some resources
created by system call A. Details about the dynamic taint-tracking module will
be presented in a future blog post.

A very simple example of a data dependency between two system calls is provided
by the next figure. Here `NtQuerySymbolicLinkObject()` operates on the handle of
a symbolic link object; this handle value is provided through its first
argument. As can be seen from the "_taint_" column for this system call, the
`HANDLE` argument is tainted with label 257 (the one highlighted in red): this
taint label identifies the system call that opened this handle, in this case
`NtOpenSymbolicLinkObject()`.

{% include custom/image.html
  src="/images/posts/qtrace-taint.png" width="711"
  caption="Data dependency between NtOpenSymbolicLinkObject() and NtQuerySymbolicLinkObject() system calls; the former defines a handle value (0x00000010) that is then used by the latter"
%}


## Conclusions ##

This post just sketched out the basic idea behind QTrace and its
architecture. QTrace is now available open source, but do not expect it to be
bug-free ;-) In some future blog posts I will discuss QTrace internals more in
detail, describing the syscall tracer, the taint-tracking engine and providing
some use cases.
