---
layout: single
title: Owning Samsung phones for fun (...but with no profit :-))
date: '2013-03-19T14:55:00.002+01:00'
modified_time: '2013-03-19T15:33:15.356+01:00'
excerpt: An overview of multiple security vulnerabilities affecting some Samsung proprietary Android components.
tags:
---

![image-right]({{ site.url }}{{ site.baseurl }}/images/posts/samsung-android.png){: .align-right}

I was planning to open a blog since some months, but I decided to do it only
now, to summarize some of the findings of a quick look I gave at a couple of
Samsung Android devices.

But let's start at the beginning. During last Christmas holidays I finally had
some free time to try to better understand the inner workings of some Samsung
devices, focusing on the manufacturer's customizations to the Android system. I
confess I was quite surprised to see how many Samsung applications are included
in the original firmware image, including several customizations to lots of
Android core packages.

To make a long story short, I soon started to find some exploitable bugs,
affecting both "old" device models (e.g., my Galaxy Tab GT-P1000) and newer
devices (e.g., my Galaxy S3). All these issues were caused by Samsung-specific
software or customizations. I must say I have nothing against Samsung: on the
contrary I'm a happy Samsung customer, and I think their phones and tablets are
quite cool, probably among the best devices around. However, their
[market share](http://online.wsj.com/article/SB10001424127887324077704578358240525192844.html)
is making them an attractive target for attackers.

I contacted Samsung at the beginning of January 2013, and on January 17th I
gave them all the technical details and proof-of-concepts for the six
vulnerabilities I found, plus some bonus denial-of-services and info leaks (for
the sake of completeness, the MD5 of my report is
`af7ca8998079c5445a3b1bcff2e05f90`). Since then, I have not received any official
confirmation from Samsung about their intention to fix these issues: as far as
I know, they are still "_in the process of checking for the
vulnerabilities_". Despite this fact, on February 20th, they asked to delay my
public disclosure until proper patches are developed, considering that "_any
patches [Samsung] develops must first be approved by the network carriers_".

In the past, I have always followed a
[responsible disclosure policy](http://googleonlinesecurity.blogspot.it/2010/07/rebooting-responsible-disclosure-focus.html)
to report the vulnerabilities I have found, but waiting until (all?) the
network carriers approve a security patch seems to be a very, VERY, long time!
Nevertheless, to avoid exposing Samsung users to possible threats, I won't
disclose any technical detail, but I think it is acceptable to provide just a
high-level overview of the issues.


## Scenario ##

All the vulnerabilities I reported can be exploited from an _unprivileged_
local application. In other words, no specific Android privileges are required
for the attacks to succeed. This allows attackers to conceal the exploit code
inside a low-privileged (and apparently benign) application, distributed
through Google Play or the Samsung Apps market.

I would like to stress out one more time that these issues are not caused by
bugs inside the "vanilla" Android system, but are all caused by
Samsung-specific software and customizations.


## Issues overview ##

As I discussed before, no technical details will be provided. In this paragraph
I will just sketch out a high-level description of the issues I found and their
possible impacts.

1. Two different vulnerabilities can be exploited to silently install
   highly-privileged applications with no user interaction. The privileged
   applications to be installed can be embedded right inside the unprivileged
   application package, or downloaded "on the fly" from an on-line market.

2. Another issue, different from the previous ones, allows attackers to send
   SMS messages without requiring any Android privilege (normally, Android
   applications are required to have the `android.permission.SEND_SMS` permission
   to perform this task).

3. An additional vulnerability can be used to silently perform almost any
   action on the victim's phone, ranging from placing phone calls to sending
   e-mails, SMS messages, and so on.


4. The remaining security issues allow attackers to change other settings of
   the victim's phone, such as networking or Internet settings, without the
   user's consent.

## Proof-of-concept ##

A video that shows the exploitation of one of the issues discussed at point 1
(stealth installation of a privileged application) is shown below. I know the
video is quite meaningless, but it is all I can disclose right now. I'm also
sorry for the poor video quality , but it turned out that recording an Android
screen video with a good fps rate is more difficult than finding 0-days :-).

<iframe width="640" height="360" src="https://www.youtube-nocookie.com/embed/uOqZZh4nlZU?controls=0&amp;showinfo=0" frameborder="0" allowfullscreen></iframe>

The video was taken using my Samsung Galaxy Tab, updated with the latest
Samsung firmware and applications available at the time of writing. A similar
vulnerability (but not the very same one) also affects the Galaxy S3 and
probably other more recent devices. The video is organized as follows:

* An application named "_Hacksung_" is installed on the target device. At the
  beginning of the video I show that "_Hacksung_" has no specific permissions.

* Application "_Hacksung_" is executed and the exploit is launched when the
  "Pwn!" button is pressed.

* The exploit installs a second app, named "_Malicious_", embedded inside the
  "Hacksung" application package. As you can see from the video, no user
  confirmation is requested.

* The application "_Malicious_" is run. This application does nothing, and it
  simply displays a text message.

* To conclude, the video shows the permissions granted to "_Malicious_". As can
  be seen, several dangerous permissions are granted, such as the ability to
  read and send SMS messages.


## Some final observations ##

The ability to silently install privileged applications or to send SMS messages
are quite appealing tasks for mobile malware authors and, to make things even
worse, most of the issues I reported to Samsung are also pretty easy to
find. As a consequence, I won't be surprised to find some malware in the wild
that exploits these or similar vulnerabilities.

Considering that most of these bugs can be fixed quite easily, without any
drastic change to the device software, I admit that I was expecting a quick
patch from Samsung. However, two months were not enough even to start the
development of a security fix, and I don't think any patch will be released
anyway soon.

I really think Samsung cares about the security of its customers, but probably
its vulnerability handling procedure should be revised a little
bit. Smartphones, tablets and other portable devices are tomorrow's computing
platform, and Android is one of the leading actors of this change. As a natural
consequence, Android malware is also rapidly growing. In this situation, the
prompt development and diffusion of security patches is simply mandatory.
