---
layout: single
title: Mac OS X local privilege escalation (IOBluetoothFamily)
date: '2014-10-30T11:54:00.000+01:00'
modified: '2014-10-31T10:08:25.826+01:00'
excerpt: Discussion of a security vulnerability affecting OS X kernel extension IOBluetoothFamily, exploitable by a local attacker to gain root privileges.
tags:
---

Nowadays, exploitation of user-level vulnerabilities is becoming more and more
difficult, because of the widespread diffusion of several protection methods,
including ASLR, NX, various heap protections, stack canaries, and sandboxed
execution. As a natural consequence, instead of extricating themselves with
such a plethora of defensive methods, attackers prefer to take the "easy" way
and started to move at the kernel-level, where sophisticated protection
techniques are still not very common (indeed, things like as KASLR and SMEP are
implemented only in the latest versions of the most popular OSes). This trend
is also confirmed by the rising number of kernel-level vulnerabilities reported
in the last few months in Windows,
[Linux](http://www.cvedetails.com/vulnerability-list/vendor_id-33/product_id-47/cvssscoremin-7/cvssscoremax-7.99/Linux-Linux-Kernel.html),
and [OS X](http://googleprojectzero.blogspot.it/).

Following this trend, we recently looked at few OS X drivers ("KEXT"s) and
found a integer signedness bug affecting service `IOBluetoothHCIController`
(implemented by the `IOBluetoothFamily` KEXT). This vulnerability can be
exploited by a local attacker to gain root privileges. The issue is present on
the latest versions of OS X Mavericks (tested on 10.9.4 and 10.9.5), but has
been "silently" patched by Apple in OS X Yosemite.


## Vulnerability overview ##

In a nutshell, the bug lies in the `IOBluetoothHCIUserClient::SimpleDispatchWL()`
function. The function eventually takes a user-supplied 32-bit signed integer
value and uses it to index a global array of structures containing a function
pointer. The chosen function pointer is finally called. As the reader can
easily imagine, `SimpleDispatchWL()` fails at properly sanitizing the
user-supplied index, thus bad things may happen if a malicious user is able to
control the chosen function pointer.

More in detail, the vulnerable part of the function is summarized in the
pseudocode below. At line 14, the user-supplied 32-bit integer is casted to a
64-bit value. Then, the "`if`" statement at line 16 returns an error if the
casted (signed) value is greater than the number of methods available in the
global `_sRoutines` array; obviously, due to the signed comparison, any
negative value for the method_index variable will pass this test. At line 20
`method_index` is used to access the `_sRoutines` array, and the retrieved
callback is finally called at line 23.

<!-- HTML generated using hilite.me -->
{% raw %}
<table style="border: none;"><tbody><tr><td><pre style="line-height: 125%; margin: 0; padding-right: 1em;"> 1<br /> 2<br /> 3<br /> 4<br /> 5<br /> 6<br /> 7<br /> 8<br /> 9<br />10<br />11<br />12<br />13<br />14<br />15<br />16<br />17<br />18<br />19<br />20<br />21<br />22<br />23<br />24<br />25<br />26</pre></td><td><pre style="line-height: 125%; margin: 0;"><span style="color: #008800; font-weight: bold;">typedef</span> <span style="color: #008800; font-weight: bold;">struct</span> {<br />  <span style="color: #333399; font-weight: bold;">void</span> (<span style="color: #333333;">*</span>function_pointer)();<br />  uint64 num_arguments;<br />} BluetoothMethod;<br /><br />BluetoothMethod _sRoutines[] <span style="color: #333333;">=</span> {<br />  ...<br />};<br /><br />uint64 _sRoutineCount <span style="color: #333333;">=</span> <span style="color: #008800; font-weight: bold;">sizeof</span>(_sRoutines)<span style="color: #333333;">/</span><span style="color: #008800; font-weight: bold;">sizeof</span>(BluetoothMethod);<br /><br />IOReturn IOBluetoothHCIUserClient<span style="color: #333333;">::</span>SimpleDispatchWL(IOBluetoothHCIDispatchParams <span style="color: #333333;">*</span>params) {<br />  <span style="color: #888888;">// Here "user_param" is a signed 32-bit integer parameter</span><br />  int64 method_index <span style="color: #333333;">=</span> (int64) user_param;<br /><br />  <span style="color: #008800; font-weight: bold;">if</span> (method_index <span style="color: #333333;">&gt;=</span> _sRoutineCount) {<br />    <span style="color: #008800; font-weight: bold;">return</span> kIOReturnUnsupported;<br />  }<br /><br />  BluetoothMethod method <span style="color: #333333;">=</span> _sRoutines[method_index];<br />  ...<br />  <span style="color: #008800; font-weight: bold;">if</span> (method.num_arguments <span style="color: #333333;">&lt;</span> <span style="color: #0000dd; font-weight: bold;">8</span>) {<br />       method.function_pointer(...);<br />  }<br />  ...  <br />}<br /></pre></td></tr></tbody></table>
{% endraw %}

## Exploitation details ##

Exploitation of this vulnerability is just a matter of supplying the proper
negative integer value in order to make IOBluetoothFamily index the global
`_sRoutines` structure out of its bounds, and to fetch an attacker-controlled
structure. The supplied value must be negative to index outside the
`_sRoutines` structure while still satisfying the check at line 16.

As a foreword, consider that for our "proof-of-concept" we disabled both
SMEP/SMAP and KASLR, so some additional voodoo tricks are required to get a
fully weaponized exploit. Thus, our approach was actually very simple: we
computed a value for the user-supplied parameter that allowed us to index a
BluetoothMethod structure such that `BluetoothMethod.function_ptr` is a valid
user-space address (where we placed our shellcode), while
`BluetoothMethod.num_arguments` is an integer value less than 8 (to satisfy the
check performed by `SimpleDispatchWL()` at line 22).

As shown in the C code fragment above, the user-supplied 32-bit value
(user_param) is first casted to a 64-bit signed value, and then used as an
index in `_sRoutines`. Each entry of the global `_sRoutines` array is 16-byte
wide (two 8-byte values). These operations are implemented by the following
assembly code:

<table style="border: none;"><tbody><tr><td><pre style="line-height: 125%; margin: 0; padding-right: 1em;"> 1<br /> 2<br /> 3<br /> 4<br /> 5<br /> 6<br /> 7<br /> 8<br /> 9<br />10<br />11<br />12<br />13<br />14<br />15</pre></td><td><pre style="line-height: 125%; margin: 0;"><span style="color: #888888;">; r12+70h points to the user-supplied index value</span><br /><span style="color: #0066bb; font-weight: bold;">mov</span>     <span style="color: #007020;">ecx</span>, [<span style="color: #996633;">r12</span><span style="color: #333333;">+</span><span style="color: #005588; font-weight: bold;">70h</span>]<br /><span style="color: #0066bb; font-weight: bold;">mov</span>     <span style="color: #007020;">r13d</span>, <span style="color: #996633;">kIOReturnUnsupported</span><br /><span style="color: #0066bb; font-weight: bold;">lea</span>     <span style="color: #007020;">rdx</span>, <span style="color: #996633;">_sRoutineCount</span><br /><span style="color: #0066bb; font-weight: bold;">cmp</span>     <span style="color: #007020;">ecx</span>, [<span style="color: #007020;">rdx</span>]<br /><span style="color: #0066bb; font-weight: bold;">jge</span>     <span style="color: #996633;">fail</span><br /><span style="color: #888888;">; Go on and fetch _sRoutine[method_index</span><span style="color: #888888;">]</span><br /><span style="color: #0066bb; font-weight: bold;">...</span><br /><span style="color: #0066bb; font-weight: bold;">movsxd</span>  <span style="color: #007020;">rax</span>, <span style="color: #007020;">ecx</span>             <span style="color: #888888;">; Sign extension to 64-bit value</span><br /><span style="color: #0066bb; font-weight: bold;">shl</span>     <span style="color: #007020;">rax</span>, <span style="color: #0000dd; font-weight: bold;">4</span>               <span style="color: #888888;">; </span><span style="color: #888888;"><span style="color: #888888;">method_index</span> *= sizeof(BluetoothMethod)</span><br /><span style="color: #0066bb; font-weight: bold;">lea</span>     <span style="color: #007020;">rdx</span>, <span style="color: #996633;">_sRoutines</span><br /><span style="color: #0066bb; font-weight: bold;">mov</span>     <span style="color: #007020;">esi</span>, [<span style="color: #007020;">rdx</span><span style="color: #333333;">+</span><span style="color: #007020;">rax</span><span style="color: #333333;">+</span><span style="color: #0000dd; font-weight: bold;">8</span>]     <span style="color: #888888;">; esi = _sRoutines[</span><span style="color: #888888;"><span style="color: #888888;">method_index</span>].num_arguments</span><br /><span style="color: #0066bb; font-weight: bold;">cmp</span>     <span style="color: #007020;">esi</span>, <span style="color: #0000dd; font-weight: bold;">7</span>               <span style="color: #888888;">; Check method.num_arguments &lt; 8</span><br /><span style="color: #0066bb; font-weight: bold;">ja</span>      <span style="color: #996633;">loc_289BA</span><br /><span style="color: #0066bb; font-weight: bold;">...</span><br /></pre></td></tr></tbody></table>

At a higher-level, the address of the `BluetoothMethod` structure fetched when processing an index value "`user_param`" is computed by the following formula:

```
	struct_addr = (ext(user_param & 0xffffffff) * 16) + _sRoutine
```

Where `ext()` is the sign-extension operation (implemented by the `movsxd`
instruction in the assembly code snipped above).

By solving this formula for `user_param` and searching inside the kernel
address space, we found several candidate addresses that matched our criteria
(i.e., a valid user-space pointer followed by an integer value < 8). The rest
of the exploit is just a matter of `mmap()`'ing the shellcode at the proper
user-space address, connecting to the `IOBluetoothHCIController` service and
invoking the vulnerable method.

The source code for a (very rough) proof-of-concept implementation of the
aforementioned exploit is available [here](http://goo.gl/4n72RL), while the
following figure shows the exploit "in action".

{% include custom/image.html
  src="/images/posts/osx-IOBluetoothFamily-shell.png" width="614"
  caption="Execution of our 'proof-of-concept' exploit"
%}


## Patching ##

We verified the security issue both on OS X Mavericks 10.9.4 and 10.9.5 (MD5
hash values for the `IOBluetoothFamily` KEXT bundle on these two OS versions
are `2a55b7dac51e3b546455113505b25e75` and `b7411f9d80bfeab47f3eaff3c36e128f`,
respectively). After the release of OS X Yosemite (10.10), we noticed the
vulnerability has been silently patched by Apple, with no mention about it in
the [security change log](http://support.apple.com/kb/HT6535).

A side-by-side comparison between versions 10.9.x and 10.10 of
`IOBluetoothFamily` confirms Apple has patched the device driver by rejecting
negative values for the user-supplied index. In the figure below, the
user-supplied index value is compared against `_sRoutineCount` (orange basic
block). Yosemite adds an additional check to ensure the (signed) index value is
non-negative (green basic block, on the right).

{% include custom/image.html
  src="/images/posts/osx-IOBluetoothFamily-fix.png" width="700"
  caption="Comparison of the vulnerable OS X driver (Mavericks, on the left) and patched version (Yosemite, on the right)"
%}


## Conclusions ##

We contacted Apple on October 20th, 2014, asking for their intention to
back-port the security fix to OS X Mavericks. Unfortunately, we got no reply,
so we decided to publicly disclose the details of this vulnerability: Yosemite
has now been released since a while and is available for free for Apple
customers; thus, we don’t think the public disclosure of this bug could
endanger end-users.


## Update (31/10/2014) ##

Yesterday evening, few hours after the publication of our blog post, we
received a reply from Apple Product Security. They confirmed the bug has been
fixed in Yosemite, and they are still evaluating whether the issue should be
addressed in the previous OS versions as well.
